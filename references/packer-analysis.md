# 加壳与保护分析（S1）+ 方案报告模板（S2）

## 零、为什么必须先查壳

盲破的典型代价：

| 盲破行为 | 后果 |
|---|---|
| 直接 `apktool d` 改 smali 重打包 | 改的是壳外壳代码，装上去逻辑没变；或壳校验签名直接闪退 |
| 直接对加壳 EXE 下断 / 改字节 | 断点落在壳解压缩代码里，跟不到真实逻辑；改字节触发完整性自校验 |
| 不看壳就选 Hook 方案 | 有反调试时 attach 即崩；或 Hook 的是壳的 stub 函数 |
| 没确认架构就写 keygen | 实际是 C 类服务端校验，本地算法根本不存在 |

**顺序不可颠倒**：查壳 → 定位 → 选型 → 出方案 → 确认 → 动手。

## 一、检测动作

```bash
# 自动（首个必跑）
python scripts/packer_detect.py <target> --json work/packer.json
python scripts/packer_detect.py <target> --deep        # 额外查混淆与可疑载荷

# 人工复核（自动结论只作定性，必须逐条对）
```

### APK 人工复核清单

1. `AndroidManifest.xml` 的 `android:name`（application）：业务 Application 还是 `StubApplication` / `ProxyApplication` / `WrapperProxyApplication`。
2. `lib/` 下有没有壳 so：`libjiagu` / `libdexhelper` / `libsecexe` / `libnqshield` / `libexecmain` …
3. `apktool d` + `jadx` 能不能读到**可读的业务代码**（有包名结构的 Activity / 业务类）。
4. dex 里能不能搜到卡密明文、验证域名 —— 能搜到说明真实逻辑没被隐藏。
5. 有没有 `assets/` 下的加密大文件（`.dat` / `.bin` 且高熵）。

### PE 人工复核清单

1. 节区名：`UPX0/UPX1`、`.vmp0`、`.themida`、`.aspack`、`.nsp0` 直接暴露壳。
2. 导入表：DLL 数量 < 3 而文件几百 KB → IAT 被壳运行时填充。
3. 熵：节区熵 > 7.2 → 压缩 / 加密。
4. `.NET`：有 CLI Header 就是 .NET，走 dnSpy，不看原生壳。
5. `IsDebuggerPresent` / `NtQueryInformationProcess` 大量出现 → 反调试。
6. `ChecksumMappedFile` / `EnumProcessModules` → 完整性自校验。

### ELF / so 人工复核清单（Android 与 Linux 通用）

1. **别信扩展名**：先读文件头。`.sh` 可能是 `#!/bin/sh` 自解压包装（`sed '1,/^__PAYLOAD__$/d' | gzip -cd | exec`），真身是后面的 ELF —— 先剥壳再看。
2. `e_shnum` 极小（如 4，仅 `.dynstr/.dynsym/.shstrtab`）→ 无 section 表，**必须按 PT_LOAD + PT_DYNAMIC 解析**（脚本按 `.rela.dyn` 找重定位会全部失效，GOT 槽空 → 仿真第一次调用就跳 0）。
3. PT_LOAD 出现 `filesz=0 / memsz=巨大`（10MB/55MB 级）→ 运行时填充区；`PT_DYNAMIC` 里 `DT_INIT/DT_PREINIT_ARRAY` 指向的内容多半是"压栈常量 + 远跳"的桩。
4. **R_AARCH64_ABS64 的 addend 是密文**（形如 `add=-0x4911391e028021d7`）→ 重定位被壳加密、运行时自解 → IDA/Ghidra 直接看全是歪地址。
5. 判"代码 / 加密数据"用**解码失败率**而不是只看熵：4KB 对齐取 4 字节喂 capstone，实测随机数据失败率 ≈64.5%，真实 aarch64 代码 ≈8–15%（按此可秒级切分 79MB 文件）。
6. **垃圾指令插入混淆**的指纹：`eor/ror/rev/orn/eon/adc/bic` 占比异常高、`ldr/str` 占比异常低、`ret` 几乎为 0（实测 22 万条指令里 12 个 ret）、大量 `mov/movk` 构造后立刻被覆盖的常量、`cbz/tbz` 依赖"恒 0/恒 1"的运算结果。
7. 找真实调用：`bl` 可能不指向 PLT —— 商业壳常改成 `adrp x16,#GOT; ldr x17,[x16,#off]; add x16,x16,#off; br x17`。
   → 用"ADRP 指向 GOT 页 + 后续 ±24 条指令内 `ldr xN,[xM,#imm]`"的模糊匹配反查**壳到底用了哪些导入**（能直接判断"判定位在不在壳里"）。
8. 中文串只剩壳自己的水印（如 `T-Protector T盾加密保护支持`）→ 业务字符串全在加密层，静态 grep 无用。

## 二、已知误报（自动判定不可盲信）

| 现象 | 真实原因 | 正确结论 |
|---|---|---|
| dex 总大小 << APK 体积 | 游戏 / 地图 / 模型资源占大头（如 370MB APK 只有 62KB dex） | **资源型大包，非壳**；直接 jadx 读 |
| dex 里出现 `payload` / `jiagu` 等词 | 普通英文词或无关字符串 | **弱特征**，需配合壳 so 或桩类名才定性 |
| 无 `lib/*.so` 且无桩类 | 纯 Java 实现 | 基本排除加固 |
| 高熵节区 | 可能是图片 / 音视频资源节，不是壳 | dump 出来看能否反汇编 |
| 导入表少 | 可能是纯静态链接的小程序 | 结合文件体积判断 |

判定规则：**只有命中「壳 so」或「加固桩类名」等强特征才定性为加固**；弱特征只作提示，落到"需人工复核"。

## 三、壳类型 → 策略矩阵

| 壳类型 | 能否直接反编译 | 能否重打包 | 推荐路线 | 回退路线 |
|---|---|---|---|---|
| 无壳（原生/明文） | 能 | 能（需重签名） | smali patch / 二进制 patch | Xposed Hook（需 root，可选） |
| Android 加固壳 | 否（只有外壳） | 大概率失败 | Xposed 脱壳模块 / 反射大师 dump dex 后再 patch | 直接改壳外壳无意义，必须先脱壳 |
| PE 压缩壳（UPX/ASPack） | 脱后能 | 能 | `upx -d` 或调试到 OEP dump + 修 IAT | 内存补丁 |
| PE 虚拟机壳（VMProtect/Themida） | 难 | 易触发自校验 | 不硬脱，内存补丁 / API Hook | 行为级绕过（mock 服务端） |
| .NET + IL 混淆 | dnSpy 能看但难读 | 能 | de4dot 去混淆 → dnSpy 改 IL | 动态调试取明文后 patch |
| ELF / so 加壳 | 看情况 | — | IDA 定位导出 / RegisterNatives 后按偏移 patch | Xposed Hook（可选） |
| **Android/Linux ELF 商业加密壳（VM 引擎类：T盾/T-Protector 等）** | 否（明文区只有壳） | **不建议**（有全文件 CRC32 自校验） | ① 先查业务方是否另有**登录器 APK**（卡密多半在那里）② 设备侧 root + 内存 dump ③ 壳级仿真（Unicorn，按 PT_DYNAMIC 填 GOT） | 有效卡密 → 抓包 → 改客户端判定分支 / hosts mock |

## 四、反调试与自校验

- 反调试：先过检测再 attach（Hook `IsDebuggerPresent` / `NtQueryInformationProcess` 返回 0；Android 侧过 `ptrace` / `TracerPid` 检测）。
- 自校验：文件级 patch 会被发现 → 优先**内存补丁**（改运行后的映像），或一并 patch 校验函数入口。
- 服务端校验：改本地不影响服务端记录，说明"仅在客户端生效"这一边界，不要声称服务端也被绕过。

## 五、方案报告模板（S2 必填）

确认前必须输出下面这份报告，等用户选 A / B 后再动手：

```markdown
## 一、保护分析结论
- 壳类型 / 混淆 / 反调试 / 自校验：（结论 + 置信度 + 证据）
- 卡密架构分类：A / B / C / D（+ 判定依据：断网、抓包、清存储三态）
- 该壳对后续动作的影响：能否反编译 / 能否重打包 / 会不会触发自校验

## 二、方案候选（≥2）
### 方案 A：<名称>
- 做法：改哪个文件 / 偏移 / 分支 / 用哪种 Hook
- 优势：…
- 代价：稳定性、是否需重打包、联网后是否失效、耗时
- 适用：<壳类型> + <架构分类>
- 失败回退：→ 方案 B

### 方案 B：<名称>
- （同上四要素）

## 三、推荐
推荐方案 X，理由：…

## 四、风险与不可逆点
- 改原文件（已备份 .bak）/ 重打包需重签 / 安装覆盖原应用 / 触发服务端风控
- 哪些改动在联网后会失效

## 五、等你确认
选 A / B / 调整 / 需要补充信息？确认前不动手。
```

## 六、GATE 硬约束

- 确认前**禁止**任何写操作：`--apply`、写补丁、回编、签名、安装、覆盖原文件。
- 只读分析不受限：解包、扫描、反编译、抓包、logcat、dump。
- 用户说"直接干 / 不用确认"时可跳过等待，但**仍必须先完成 S1 并输出报告**。
- 报告中必须区分事实（有证据）/ 推断（有部分依据）/ 假设（待验证，标 E# 编号）。
