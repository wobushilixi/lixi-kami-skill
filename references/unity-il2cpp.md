# Unity 游戏卡密破解：Mono 与 IL2CPP 双路线

> **为什么单独一节**：市面上外挂/游戏辅助绝大多数是 Unity 做的。Unity 目标用 jadx/apktool 路线**只能看到空壳**——`jadx` 打开只有 `UnityPlayerActivity` 和 SDK 胶水代码，游戏逻辑全在 Unity 引擎层。走错路线 = 从第一步就注定失败。**S1 分析时必须先做本节的引擎识别**。

## 1. 三秒识别引擎类型（解包后看文件）

```bash
unzip -l target.apk | grep -E "libil2cpp|libmono|Assembly-CSharp|global-metadata"
```

| 找到的文件 | 引擎 | 难度 | 走哪条路 |
|---|---|---|---|
| `assets/bin/Data/Managed/Assembly-CSharp.dll` + `libmono*.so` | **Mono** | ⭐ 简单 | 路线 A：dnSpy 直接改 DLL |
| `lib/arm64-v8a/libil2cpp.so` + `assets/bin/Data/Managed/Metadata/global-metadata.dat` | **IL2CPP** | ⭐⭐⭐ 较难 | 路线 B：Il2CppDumper 还原符号 |
| `libil2cpp.so` 存在但**没有** `global-metadata.dat` | IL2CPP + 加密元数据 | ⭐⭐⭐⭐ | 先脱壳/内存 dump 元数据，见第 4 节 |
| 两者都没有 | 不是 Unity | — | 回到常规 smali / native 路线 |

补充判定：`assets/bin/Data/` 下有 `level0`、`sharedassets0.assets`、`unity default resources` 等文件 = Unity 实锤（即使 lib 目录被抽）。

## 2. 路线 A：Mono（简单，首选试试）

C# 编译成 IL，`Assembly-CSharp.dll` 可直接反编译回 C#：

1. 解包提取：`unzip -j target.apk 'assets/bin/Data/Managed/*.dll' -d out/`
2. 用 **dnSpy / dnSpyEx / ILSpy** 打开 `Assembly-CSharp.dll` —— 能看到完整 C# 源码
3. 搜卡密语义：`License`、`Card`、`Key`、`Verify`、`Login`、`VIP`、`Expire`、`激活`、`验证`
4. 修改方式二选一：
   - **dnSpy 直接编辑**（Edit Method / Edit Class）：改判定方法恒返回 true，dnSpy 可直接编译保存 DLL
   - IL 侧 patch 后用 `ilspycmd` 反编译确认
5. 把改好的 DLL 替换回 APK 内 `assets/bin/Data/Managed/Assembly-CSharp.dll`，重打包 + 签名（流程同常规，注意 zipalign + v2 签名）

**常见坑**：
- 作者会加密/压缩 Assembly-CSharp.dll（头两字节不是 `MZ`）→ 先解密或走脱壳
- 有的卡密校验放在 Unity 引擎的 native 插件（`lib/*.so`）→ 结合路线 B 的 patch 方法
- Mono 版本 DLL 有 `Assembly-CSharp-firstpass.dll`（第三方库）也要检查

## 3. 路线 B：IL2CPP（主流，实战 playbook）

C# → IL → C++ → native `libil2cpp.so`，C# 元数据被剥离到 `global-metadata.dat`。**两个文件单独都没用，必须配对**。

### 3.1 用 Il2CppDumper 还原符号

```
Il2CppDumper.exe libil2cpp.so global-metadata.dat output/
```

产出物及用途：

| 文件 | 用途 |
|---|---|
| `dump.cs` | **先读这个**——全部 C# 类/方法/字段 + 每个方法的 RVA 地址 |
| `DummyDll/` | 壳 DLL（无实现），用 dnSpy/ILSpy 打开浏览类型结构 |
| `script.json` + `il2cpp.h` | 喂给 IDA/Ghidra 的符号恢复脚本 |
| `stringliteral.json` | 所有字符串常量及其地址（**搜卡密文案/URL 的金矿**） |

失败处理：版本不匹配报错先试 `--force-version`；还不行换 **Il2CppDumperEx / Il2CppInspector**（支持更新的 Unity 版本和加密 metadata）。

### 3.2 定位卡密判定点（不需要真机，纯静态）

```bash
# 在 dump.cs 里搜卡密语义
grep -n -i "license\|cardkey\|verify\|isvip\|checkcard\|expire" output/dump.cs
# 在 stringliteral.json 里搜文案
grep -i "激活成功\|卡密错误\|验证失败\|invalid" output/stringliteral.json
```

`dump.cs` 里每个方法带着地址注释：

```csharp
public class CardManager {
    // RVA: 0x1A2B3C4 Offset: 0x1A2A3C4
    public bool VerifyCard(string card) { }
}
```

### 3.3 Patch libil2cpp.so（核心操作）

到 RVA 对应的函数地址，把**验证方法改成恒返回 true**（aarch64）：

```
方法开头两条指令替换为：
MOV W0, #1        ; 52 80 00 20 → 返回 true
RET               ; D6 5F 03 C0
```

- 地址换算：**文件偏移 = RVA − (该函数所在段的 vaddr − 段文件偏移)**；多数情况 `Offset`（dump.cs 里第二个值）就是文件偏移
- 工具：010Editor / imhex 打开 `libil2cpp.so` 跳到偏移，直接改机器码
- 改完替换回 APK → 重打包 → 对齐（`zipalign4.py`）→ 签名（v1+v2）

**参照（bool 返回以外的形态）**：
- 返回 `int`（VIP 等级）→ `MOV W0, #9`（改大）或按语义给值
- 返回 `string` / `void` / 对象 → **不能改方法头**，去 dump.cs 找它的**调用方**，改调用方的分支判断（`CBZ`→`NOP` 或反转 `B.EQ`）
- 协程方法（名字带 `MoveNext`/`d__xx`）→ 真实逻辑在状态机类里，搜 `IEnumerator` 同名类

### 3.4 IDA/Ghidra 符号恢复（要细看逻辑时才做）

- IDA：File → Script file → `ida_with_struct_py3.py`，喂 `script.json` → 所有 `sub_xxx` 变成 `ClassName$$MethodName`
- Ghidra headless：`analyzeHeadless ... -postScript ghidra_with_struct.py output/script.json`

## 4. metadata 加密 / 缺失时（先脱壳再回来）

`global-metadata.dat` 被加密的标志：文件头不是 `AF 1B B1 FA`（标准 magic）。

1. **BlackDex**（无需 root）跑一遍目标 → 拿到运行时 dump 的 `libil2cpp.so` 与 metadata（见 `unpack-repack.md`）
2. 或 **Zygisk-Il2CppDumper**（需 root+Magisk）：运行时自动 dump 解密后的 metadata
3. 拿 dump 出的文件重跑第 3.1 步；注意 dump 的 so 里部分函数未解密，需主动触发对应功能再 dump

## 5. Unity 特有的坑

| 现象 | 真因 | 处理 |
|---|---|---|
| patch 后游戏崩溃在 `il2cpp_init` | metadata 与 so 版本不配对 | 确保两个文件来自**同一次 dump/同一版本** |
| 改了 IsVip 界面不变 | UI 状态缓存在别处（PlayerPrefs） | 顺带清 `sharedprefs` 里的 vip/expire 键 |
| 改完本地验证过了，联网又变回去 | 服务端心跳纠正（C 类） | 加响应拦截/mock，或连判定方法的调用方一起改 |
| Il2CppDumper 报 "unsupported" | Unity 版本太新/加密 | 换 Il2CppInspector；或先 BlackDex 内存 dump |
| `dump.cs` 里搜不到任何卡密词 | 字符串加密，或逻辑在 IL2CPP 之外的插件 so | 搜 `stringliteral.json`；再查 `lib/` 下的非 il2cpp so |
