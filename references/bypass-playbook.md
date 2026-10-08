# 绕过手法手册：选型、回退、验证、交付

## 一、决策顺序

```
壳分析结论 ──┬─ 有强壳 ──→ 先脱壳 / 走运行时 Hook（不重打包）
             └─ 无壳   ──→ 架构分类 A/B/C/D
                              │
     ┌────────────────────────┼────────────────────────┐
     A 本地算法               B 本地+网络              C 服务端主导 / D 试用
     │                        │                        │
 算法还原→keygen          本地 patch + 网络 mock    mock server / 响应 Hook
 或 patch 判定分支         或改响应解析后判定      或时间冻结 / 计数重置
```

**选最小代价**：能 Hook 就不重打包；能 patch 一个分支就不改算法；能改本地判定就不碰网络。

## 二、手法明细与失效条件

| 手法 | 适用 | 失效条件 | 备注 |
|---|---|---|---|
| smali 方法头恒返回 | 无壳 APK，返回类型为 `Z`/`I` | 壳签名校验；方法被多处复用 | 用 `smali_kami_patch.py` |
| smali 分支反转 | 单个 `if-eqz` 决定成败 | 多处判定 | 改前确认分支唯一 |
| so 二进制 patch | native 判定 | 完整性校验；so 被重新加载 | 改 `MOV R0,#0`→`#1` 或反转 `CMP` 后跳转 |
| Xposed / LSPosed Hook | 任意（不重打包） | 需 root；有反调试时可能失效 | 可选验证手段，需设备支持；静态 patch 才是主力 |
| 二进制 patch（PE） | 无壳 EXE | 自校验 | 保持指令长度不变 |
| DLL 劫持 | 有固定依赖 DLL | 程序用绝对路径加载 | 转发原导出 |
| mock server + hosts | B / C 类 | 证书校验 / 证书绑定 | 本地起服务，不打真实服务端 |
| 响应 Hook | B / C 类 | 响应有签名，客户端验签 | 需同时处理验签或改解析后判定 |
| 时间冻结 | D 类 | 有"时间回退检测" | 同时 patch 比较逻辑 |
| 计数重置 | D 类 | 服务端记录次数 | 仅客户端生效 |

## 三、回退决策树

```
patch 后仍要求激活
  ├─ 是否命中别的判定分支？ → 是：回到 S1 重新动态确认（可能不止一个判定点）
  ├─ 是否联网后失效？       → 是：B/C 类，补网络层方案（mock / 响应 Hook）
  ├─ 是否启动即闪退？       → 是：触发自校验或签名校验 → 改走内存补丁 / Hook
  └─ 是否根本没改到目标？   → 是：壳没脱干净，回 S1
```

## 四、验证规范

1. **三态验证**：断网启动一次、联网启动一次、清除本地状态后再启动一次，都过才算通过。
2. **真实输出**：贴实际命令与程序表现；没跑的步骤写 `未执行` 并给下一条命令。
3. **不编造**：哈希、偏移、响应内容、成功结论必须是真实观察到的。
4. **副作用检查**：确认没有请求真实第三方服务、没有覆盖用户原文件（有 `.bak`）。

## 五、常见坑

- **重打包必重签**：v1 用 `jarsigner`，v2/v3 必须用 `apksigner`；`zipalign` 在签名前做。
- **Android 7+ 抓 HTTPS**：用户 CA 默认不被信任，需在 `network-security-config` 里配置或把证书装到系统分区。
- **smali 寄存器冲突**：`.locals 0` 时不能用 `v0`；脚本会自动提到 `.locals 1`，但手工改时要注意。
- **返回类型不符**：返回 `V`/对象的方法不能靠"方法头恒返回"绕过，要改**调用点**。
- **Unity / IL2CPP**：`libil2cpp.so` + `global-metadata.dat`，判定点在 native，需 Il2CppDumper 还原符号后再 Hook。
- **多 dex**：主 dex 找不到就搜 `classes2.dex`、`classes3.dex`。
- **资源 ID 偏移**：改 `resources.arsc` 或增删资源会导致 id 错位，尽量不动资源。
- **apktool 回编译在中文路径必挂**：aapt2 报 `failed to open directory`，实际是路径被 GBK 乱码。把解包目录复制到纯 ASCII 路径（如 `C:\Users\Administrator\qhbuild`）再 `apktool b`，370MB 大包约 10 秒完成。
- **无 Android SDK 也能对齐签名**：`java -jar uber-apk-signer.jar -a x.apk --allowResign --overwrite`，内置 zipalign(BUILT_IN) 与 debug keystore，输出 v1/v2/v3 并自动 verify。
- **smali 分支语义反直觉**：`if-eqz p0, :lab` 是 `p0 == 0/null` 时跳转。写"非空才继续"的判空分支极易写反，null 入参会 NPE——必须把 null 也纳入验证用例。
- **无真机/无模拟器的动态验证**：`apktool b` 得到 dex → dex2jar 2.0(`java -cp "lib/*" com.googlecode.dex2jar.tools.Dex2jarCmd x.dex -o x.jar`) → 写 Java harness 用反射调用目标静态方法，缺 `org.json` 等依赖时补对应 maven jar。能直接读到 `success` 字段真值；且补丁若真的离线，调用会瞬间返回且无网络异常，本身也是"未联网"的旁证。**注意要对最终交付 APK 里的 dex 再跑一遍**，别只验中间产物。

## 六、交付清单

```
1. 保护分析结论（壳 / 混淆 / 反调试 / 自校验 + 证据）
2. 卡密架构分类 A/B/C/D + 三态判定依据
3. 判定点清单（文件:位置 + 证据 + 是否已动态确认）
4. 方案候选与用户选择结果
5. 产物路径：补丁文件 / smali diff / Hook 脚本 / mock server 代码 / 备份 .bak
6. 复现命令（回编、签名、安装、运行）
7. 验证结果（三态）+ 未执行项
8. 已知失效条件与边界
```

## 七、增效手法（提升一次成功率）

### 1. 多判定点枚举（改一个不够的高频原因）

会员/授权状态通常由一组方法共同决定，只改 `isVip()` 界面仍会显示未激活。

```bash
# 把同族方法全列出来
grep -rniE "isvip|ispro|ismember|isactive|isvalid|isexpired|islicensed|viplevel|vipstate|vipflag" work/smali
```

对齐后用 `scripts/smali_kami_patch.py --keywords <这些关键词>` 一次性全部 patch，或（设备支持 Xposed 时）用 `scripts/xposed_kami_module.java` 的 `METHOD_PATTERNS` 批量强制返回，再逐个去掉，反推出哪个才是真判定点。

### 2. Windows 侧：从输入/输出回溯，比正向读代码快

| 断点 | 作用 | x64dbg 操作 |
|---|---|---|
| `GetDlgItemTextA/W` | 卡密输入框取值的瞬间 | 命令行 `bp GetDlgItemTextA` |
| `MessageBoxA/W` | 弹出"卡密错误"的瞬间 | 命中后看调用栈往上一层 |
| `lstrcmpA/W` / `memcmp` | 卡密与正确值比较 | 命中后看参数即真值 |
| `WM_LBUTTONUP` | 点"激活"按钮 | 从按钮事件往下跟 |

顺序建议：先 `MessageBoxA` 断点触发一次失败 → 回溯调用栈 → 找到判定跳转 → 再确认输入来源。

### 3. 网络型：先判断能不能改包

```bash
# 抓一次成功/失败的请求，对比响应字段
# 看三件事：
#   1) 响应里有没有 sign / signature 字段（有 → 改包无效）
#   2) 请求里有没有 timestamp + nonce（有 → 重放无效）
#   3) 到期时间是服务端返回还是本地算的（本地算 → 改本地即可）
```

有签名的响应不要浪费时间伪造，直接改**客户端解析响应后的判定分支**（几乎总有效）。

### 4. 时间型：冻结要配套

只冻结 `GetSystemTime` / `currentTimeMillis` 会被"时间回退检测"识破（程序记住上次启动时间，发现变小就判定异常）。配套动作：同时 patch 时间比较逻辑，或每次都把时间推到未来的固定值。

### 5. 失败回退顺序（别卡死在一条路上）

```
Hook 验证失败 → 放弃动态路线，改回静态 patch（本 Skill 默认路线）
判定点改了没反应 → 枚举同族方法 / 换从输出回溯定位
patch 后装不上/闪退 → 过签名校验 / 过完整性校验 / 退回 Hook 路线
本地改了联网失效 → B、C 类，补网络层（mock / 响应 Hook）或只改客户端判定
响应带签名改不动 → 放弃改包，改客户端判定点
壳脱不出来 → 放弃静态，全走运行时 Hook（不改文件）
```

