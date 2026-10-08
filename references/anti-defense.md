# 对抗层：签名校验 / 反调试 / 完整性校验 / 机器码绑定

> 卡密改不下来，八成不是判定点找错，而是**倒在这些对抗层上**：改完 smali 装上弹"验签失败"、程序启动自退出、卡密绑死设备。
> **本文件所有方案默认走静态 patch 路线，不依赖任何注入框架。**

## 一、签名校验（重打包后最常踩的头号问题）

改完 smali 重打包、重签 → 启动弹"验签失败 / 参数错误"。原因是程序在运行时比对自身签名，而你用了另一把钥匙签名。

### 定位

- Java 层：`getPackageInfo(pkg, GET_SIGNATURES)`、`PackageManager`、`Signature`、`hashCode()`、`toCharsString()`、与硬编码字符串比较。
- native 层：常见函数名 `checkSignUseApplicationPackageManager`（未混淆时很好认）、用反射调 `PackageManager`。
- 快捷判断：`python scripts/packer_detect.py <target>` 会直接报"签名校验"命中项。

### 三种打法（代价从低到高）

1. **改比较分支（推荐，纯静态）**
   找到比对后的判定跳转，反转即可：

   ```
   invoke-virtual {v0, v1}, Ljava/lang/String;->equals(...)Z
   move-result v0
   if-eqz v0, :cond_fail      ← 改成 if-nez（或改成 goto :cond_success）
   ```

   或直接把失败分支的 `const/4 v0, 0x0` 改成 `0x1`。

2. **改 so（校验在 native 时）**
   IDA 定位返回值赋值处，改 ARM64 立即数。
   例：`MOV W8, #2`（校验失败）→ `MOV W8, #1`。ARM64 小端，机器码 `52 80 00 48` → `52 80 00 28`，用 010Editor / HxD 全局替换后保存。
   （位域规则：立即数在第 5–20 位，`#2` = `0100000000000000`，`#1` = `1000000000000000`。）

3. **一键工具（新手最省力）**
   MT 管理器 / NP 管理器 / 核心破解插件：自带"去除签名校验"和一键重签，改完 smali 直接点即可。

4. **Xposed 伪造（可选，需 root）**
   先用观察模式拿到真实 `hashCode()` 与 `toCharsString()`，填进 `scripts/xposed_kami_module.java` 的 `FAKE_SIGN_HASHCODE` / `FAKE_SIGN_CHARS`，绕过比对而不用改文件。

## 二、反调试 / 反注入

要点：**这类检测只影响"动态调试"路线，对静态 patch 路线基本无影响**。看到有反调试不用慌，直接改文件即可；只有当你想挂调试器时才需要处理。

| 检测 | 静态打法（推荐） | 想调试时才需要 |
|---|---|---|
| `Debug.isDebuggerConnected()` | smali 里把调用结果覆盖：`const/4 v0, 0x0` 替代 `move-result v0` | — |
| `android.os.Debug.waitForDebugger` | 同上或直接删调用 | — |
| `TracerPid` / `/proc/self/status` | 改读文件的比较分支 | 改 `/proc` 读取结果 |
| `/proc/self/maps` 扫描注入模块 | 对静态路线无影响，可忽略 | 需屏蔽加载来源 |
| Windows `IsDebuggerPresent` | patch 调用点返回 0 | Hook 返回 FALSE |
| `NtQueryInformationProcess`(DebugPort) | patch 调用点 | Hook 返回 0 |
| 时间差检测（GetTickCount / rdtsc） | patch 时间比较逻辑 | Hook 时间函数 |
| 发现调试就自杀（System.exit / ExitProcess） | 把 `System.exit` 调用 NOP 掉 | — |

## 三、完整性自校验

- 表现：改完文件直接闪退、提示文件损坏、卡在启动页。
- 检测方式：读自身 APK/EXE 算 CRC/MD5、比对 `classes.dex` 大小、Windows 侧 `ChecksumMappedFile` / `EnumProcessModules`。
- 对策（按代价）：
  1. **把校验函数一起 patch 掉**：让它恒返回"正常"（最常用）。
  2. 用去签/去校验工具（MT/NP 管理器）顺手处理。
  3. 分页解密 + 用完即擦的壳（内存里拿不到完整明文）→ 只能改判定点，不要试图 dump 整个 dex。

## 四、机器码（HWID）绑定

- 采集源：Android 侧 `Build.SERIAL` / `Build.FINGERPRINT`、`Settings.Secure.ANDROID_ID`、`TelephonyManager.getDeviceId`、`WifiInfo.getMacAddress`；Windows 侧多为硬盘序列号 / CPU ID / 主板 UUID（`GetVolumeInformation`、WMI 查询）。
- 静态打法：patch 采集函数，让它返回固定字符串（smali 里在方法头插 `const-string v0, "固定值"` + `return-object v0`）。
- 注意：服务端若同时记录设备指纹并复核，伪造机器码只在**首次绑定**时有效；已绑到别的机器需配合清本地状态或改客户端判定点。

## 五、处理顺序决策树

```
改完装上弹"验签失败" ──→ 过签名校验（改比较分支 / 改 so / MT·NP 管理器去签）
   ↓ 能启动
装上直接闪退 ─────────→ 过完整性校验（patch 校验函数）或检查 smali 语法与寄存器
   ↓ 能跑
界面仍显示未激活 ─────→ 还有别的判定点，回去枚举同族方法
   ↓
卡密绑设备换机失效 ───→ patch 机器码采集函数，或清本地状态
   ↓
想挂调试器却崩 ───────→ 过反调试；或干脆不调试，直接静态 patch
```
