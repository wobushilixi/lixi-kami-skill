# 无 Root 脱壳与修复重打包全流程（BlackDex 路线）

> **适用场景**：packer_detect 判定有壳（抽取壳/内存加载壳），或 jadx 打开看不到真实代码（类名是 `0O0O0` / Stub / 逻辑残缺）。**全程不需要 root、不需要 Frida**——用户环境友好度最高的脱壳方案。
> 前提：需要一台安卓真机或模拟器（5.0~12），把目标 APK 装上去跑一次。

## 0. 先判断到底要不要脱壳

脱壳成本不低，先过这道闸：

| 现象 | 结论 |
|---|---|
| jadx 能看到完整业务代码，只是混淆 | **不用脱壳**，直接 smali patch |
| jadx 里类名 `com.stub.StubApp` / `s.h.e.l.l` / `0O` 开头，业务代码缺失 | 要脱壳 |
| `packer_detect.py` 判定加固壳 + 用户反馈"逻辑看不到" | 要脱壳 |
| 只有 dex 体积小、但 `assets/` 里是游戏资源 | **不用脱壳**（资源型大包误判，见 packer-analysis.md） |

## 1. BlackDex 脱壳（手机端，零环境依赖）

- 工具：BlackDex（分 32/64 位两个 APK，按目标App 位数装对应版本）
- 支持一代（落地加载）/ 二代（内存加载）/ 三代（指令抽取）壳；支持 Android 5.0~12；模拟器可用
- 操作：装 BlackDex → 打开 → 列表里找到目标 App → 点一下 → 几秒到几分钟出结果

产出两个目录的 dex：
- `hook_*.dex`：hook 系统 API 脱出的 dex
- `cookie_*.dex`：通过 DexFile cookie 脱出的 dex（**深度脱壳时会自动修复，优先用这个**）

**已知限制**（如实告知用户）：
- 深度脱壳（修复抽取指令）可能失败或闪退；需要"主动调用才解密"的指令无法回填（nop 问题）
- 拿到的 dex 可能不完整——多个 dex 对比大小，与原包 dex 大小相同的可丢弃

## 2. 修复 dex（NP 管理器）

1. 把脱出的 dex 传到电脑（或直接手机上操作）
2. **NP 管器**打开每个 dex → 功能 → **修复 dex（全部修复）**——回填被抽取的方法指令，解决方法体是 nop 的问题
3. 修复后用 jadx 打开验证：能看到真实业务类 = 修复成功；还是空的 = 换 cookie 版 dex 或换深度脱壳

## 3. 替换回 APK（还原真实结构）

1. `apktool d`（或 zip 直接解）原 APK
2. **找到真实 Application 类名**：用 baksmali 反编译脱出的主 dex，全局搜：
   ```
   .field static className:Ljava/lang/String;
   ```
   其赋值（`const-string`）就是真实入口，如 `com.xxx.MyApp`
3. 改 `AndroidManifest.xml`：`<application android:name="...">` 换成真实类名
4. **删除壳的痕迹**：
   - 根目录所有 `classes{n}.dex` 删掉，把修复好的 dex 重命名为 `classes.dex`、`classes2.dex`… 放回去
   - 删 `0O0O0…` 之类乱码文件、`tencent_stub`、`tosversion`、名字带 shell/stub 的 so
   - `lib/*/` 里的壳 so（`libjiagu*`、`libexec*`、`libshell*` 等）删掉
5. `apktool b` 回编 → **zipalign（`zipalign4.py`）** → v1+v2 签名 → 安装

⚠️ 删壳 so 前，先确认业务代码不依赖它（jadx 搜 `System.loadLibrary` 引用的库名）。

## 4. 替代脱壳方案（BlackDex 失败时）

| 方案 | 环境要求 | 说明 |
|---|---|---|
| dumpDex（Xposed 模块） | root + LSPosed | Hook `Instrumentation.newApplication` / `ClassLoader.loadClass` 拿 dex |
| FART / FARTActive | 定制 ROM | 主动调用组件，对抽取壳修复率高，环境门槛最高 |
| MT 管理器「脱壳」功能 | 无 root | 内置简易脱壳，浅壳够用，先试它成本最低 |
| 内存 dump（`/proc/<pid>/maps` + dd） | root | 手动方式，最后手段 |

## 5. 脱壳后的路

脱壳 ≠ 破解成功，只是拿到了能看的代码。回到主线：
- smali 定位判定点 → `smali_kami_patch.py` → 回编签名（四阶段照走）
- 若是 Unity 包，dex 里只有胶水，继续按 `unity-il2cpp.md` 处理 native 层
