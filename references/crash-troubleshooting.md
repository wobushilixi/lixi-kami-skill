# 补丁后闪退 / 无效：系统化排查手册

> **适用场景**：smali/so 已 patch、回编签名安装都成功，但 App 一开就闪退 / 点某功能闪退 / 功能无效。**这是实战中"破解失败"的最大来源**——不是没找到判定点，而是改完之后倒在这一步。按本手册顺序排查，不要瞎猜。

## 0. 铁律：先拿崩溃日志，再动脑子

一切猜测都不如一行 logcat：

```bash
adb logcat --pid=$(adb shell pidof <包名>)   # 或
adb logcat | grep -E "FATAL|AndroidRuntime|<包名>"
```

崩溃日志直接给出：**异常类型 + 崩溃的类名 + 方法名**。没有日志就排查 = 赌博。拿不到日志（没设备）时，按第 4 节静态自查。

## 1. 按 logcat 异常类型分诊

| logcat 异常 | 真因 | 修法 |
|---|---|---|
| `VerifyError` / `rejecting class` | smali 语法/寄存器/类型冲突（死代码残留） | 用 `verify_patch.py` 查目录；确认用了 `--mode replace` 整体替换方法体 |
| `NoSuchMethodError` / `NoSuchFieldError` | 改动引用了不存在的方法（多 dex 漏改 / 调用点改错） | 全局搜该方法所有调用点；确认 dex 没漏（classes2/3.dex） |
| `NullPointerException` | NOP 掉了关键初始化 / 判定方法的返回值被解引用 | 不要 NOP 分支，改成改条件跳转（`CBZ`↔`CBNZ`）；或给返回值兜底 |
| 无异常直接 `Process terminated` / `System.exit` | **签名校验命中**（见第 2 节）或完整性校验（第 3 节） | 不是崩溃，是主动自杀 |
| `UnsatisfiedLinkError` | 删了壳 so 但业务还在加载 / so 被改坏 | 恢复被删的 so；核对 so patch 是否越界写坏 ELF |
| 原生崩溃（`SIGSEGV`/`tombstone`） | so 补丁地址算错 / 写坏指令边界 | 核对 RVA→文件偏移换算；检查是否覆盖了相邻指令 |

## 2. 签名校验三层（最高频闪退原因）

App 检测到重签名后主动 `System.exit` / `killProcess`。**三层都要查**，只处理 Java 层经常不够：

### 2.1 Java 层（最容易）
jadx 搜"签名三兄弟"：`signature`、`killProcess`、`getPackageManager`。改法：
- 让校验方法恒返回 true（`smali_kami_patch.py`）
- 或让签名比较恒相等

### 2.2 so 层（native 校验，Java 绕过无效）
特征：Java 层搜不到校验代码，但重打包必闪退。
- jadx 搜 `native` 方法 + `System.loadLibrary`，锁定业务 so
- IDA/Ghidra 打开 so，搜字符串 `signature` / `Signature`，或找 JNI_OnLoad / RegisterNatives 里注册的函数
- 常见实现：调 `Signature.hashCode()` 与硬编码值比对，不等就 `exit()`
- 修法（三选一，按代价从小到大）：
  1. **patch so 分支**：把比较后的条件跳转改反转或恒不跳（见 `elf-binary-card-key.md` 的跳转改写表）
  2. **epic / 太极 / 应用转生（非 root hook）**：写个小 dex hook `Signature.hashCode()` 返回正确 hash，塞进 APK 主动调用——原 so 是内存 dump 出来改不了时唯一选择
  3. 在线签名校验：抓包拿服务端返回的正确签名值，回填到本地比对处

### 2.3 一键去签（成本最低，先试）
**MT 管理器 / NP 管理器的「去除签名校验」**：原理 = `killPM`（hook PMS 伪造签名）+ `killOpen`（IO 重定向，让读 APK 的代码读到原始包）。无 root 可用。**闪退且怀疑签名校验时，先用它试，成了再决定要不要手工做**。

### 2.4 完整性校验（Dex CRC / APK hash）
- 特征：Java 层有 `getEntry("classes.dex").getCrc()` / `MessageDigest` + APK 全文件 hash 比对
- 修法：改比对常量为新值（算出新 dex 的 CRC/hash 填进去），或让校验函数恒 true
- so 层做文件 hash 校验时，hook/patch 读文件处，或用 IO 重定向思路（把读路径指回原 APK）

## 3. 逻辑无效（不崩，但功能没解锁）

| 现象 | 真因 | 修法 |
|---|---|---|
| 改了 `isVip()` 界面还是未激活 | **同族判定点漏改** | 全局搜同族：`isVipExpired` / `getVipLevel` / `vipFlag` / `checkAuth`，一起改；UI 还会读 `SharedPreferences` 缓存 → 清数据再试 |
| 只在断网时有效 | C 类服务端心跳纠正 | mock / 改响应解析（见 bypass-playbook） |
| 改了 A 处，B 功能又弹验证 | 多入口多处校验（时间触发/延迟校验） | 遍历主要功能逐个触发，把每次新弹的校验点记入 E# 台账继续改 |
| 改了没任何反应 | 补丁点根本没被执行（定位错了） | 回 S1 用动态证据（logcat/抓包）确认真实判定点，别凭字符串猜 |

## 4. 没设备时的静态自查（S4 收口）

没有 logcat 就按序自查（每项都有工具支撑）：

1. `verify_patch.py <smali目录>` —— 语法 / 寄存器越界 / **死代码**（VerifyError 主因）
2. `verify_patch.py <apk>` —— dex / manifest / v1+v2 签名
3. `zipalign4.py check <apk>` —— 未对齐 = -124 装不上
4. **二分法回溯**（多个修改点时）：先只保留 1 个修改点 → 回编签名（模拟用户安装）→ 逐个叠加。哪个叠上去出问题就锁定哪个——静态无法定位时的最后手段
5. 重新审视被改方法的**调用链**：返回值被谁消费？有没有解引用/NPE 风险？写清楚"逻辑自证"

## 5. 回编与安装层的问题（不是逻辑问题）

| 现象 | 原因 | 修法 |
|---|---|---|
| apktool 回编报错 | 中文路径（GBK 乱码）/ 资源 id 错位 | 复制到纯 ASCII 路径；尽量只改 smali 不动资源 |
| `-124 INVALID_APK` | **漏 zipalign** | `zipalign4.py` |
| `INSTALL_PARSE_FAILED_NO_CERTIFICATES` | 没签名 / 只签了 v1 而 targetSdk 要求 v2 | apksigner v1+v2 都签 |
| `INSTALL_FAILED_UPDATE_INCOMPATIBLE` | 设备上有原包残留 | 先 `adb uninstall` 原包 |
| 装上了但图标消失/秒退 | manifest 的 application 名指向被删的壳类 | 见 unpack-repack.md 第 3 步，换回真实类名 |
