# Windows EXE / DLL 卡密链路

## 一、先分类再动手

| 类型 | 快速判定 | 主路径 |
|---|---|---|
| 本地算法 | 断网可用、无联网域名、有哈希/异或运算 | 算法还原 → keygen，或 patch 判定分支 |
| 本地 + 网络 | 首次联网激活，之后离线可用 | patch 判定 + 响应替换 |
| 服务端主导 | 断网直接拒绝，每次启动请求 | mock server / hosts / 响应 Hook |
| 试用计数 | 注册表、授权文件、剩余天数 | 时间冻结 / 计数重置 / patch 判定 |

**三态对比法**：断网运行一次 → 抓一次流量 → 清一次本地状态，再下结论。禁止只凭字符串猜。

## 二、静态定位

```powershell
# 基础信息
Get-FileHash target.exe -Algorithm SHA256
Get-Item target.exe | Select-Object Length, VersionInfo

# 字符串（含 Unicode）
strings64.exe -n 6 target.exe | Select-String -Pattern "license|activate|serial|key|trial|expire|register|invalid"
strings64.exe -u -n 6 target.exe | Select-String -Pattern "激活|授权|卡密|注册码|试用|已过期"

# 导入表线索（网络 / 加密 / 时间 / 注册表的组合直接暴露架构）
dumpbin /IMPORTS target.exe   # 或 rabin2 -i target.exe
rabin2 -i target.exe | Select-String "WinHttp|WinInet|WS2_32|Crypt|Advapi32|GetSystemTime"
```

导入表速判：
- `WinHttp/WinInet/WS2_32` → 有网络校验（B/C 类）
- `Crypt*` / `BCrypt*` → 本地签名或哈希校验（A/B 类）
- `Advapi32!RegSetValueEx` + `GetSystemTime` → 试用计数（D 类）

## 三、壳与语言识别

```bash
rabin2 -I target.exe        # 基本信息
peid / die target.exe       # 查壳：UPX / VMProtect / Themida / ASPack / .NET
```

- **UPX**：`upx -d target.exe` 直接脱。
- **VMProtect / Themida**：不硬脱，改走内存补丁或 API Hook。
- **.NET**（有 `mscoree.dll` 导入）：dnSpy / ILSpy 直接出源码，判定点最清晰，可右键"编辑方法"直接改 IL 后保存。
- **易语言 / VB / Delphi**：特征库字符串明显，Delphi 用 IDR/DeDe，易语言看 `krnln`；多为本地算法 + 网络校验混合。

## 四、判定点与补丁形态

x86/x64 常见判定：

```asm
call    sub_401000          ; 校验函数
test    al, al
jz      short loc_fail      ; 失败分支  ← patch 点
; 成功流程
```

三类改法：

1. **反转跳转**：`74 xx`(JZ) → `75 xx`(JNZ)，或 `75` → `74`。改动 1 字节。
2. **强制跳转**：`jz loc_fail` → `jmp loc_ok`（`EB`），或把两条都填 `90`(NOP)。
3. **函数头恒返回**：`MOV EAX, 1` + `RET`（`B8 01 00 00 00 C3`）。

工具：x64dbg（汇编里直接改 + 补丁到文件）、HxD、CFF Explorer。

注意：
- 改跳转时保持指令长度一致，否则后续偏移全乱。
- x64 下注意 `test al,al` 与 `test eax,eax` 的区别，以及 RIP-relative 寻址不能直接搬移。
- 有自校验（CRC / 完整性检查）的程序，改文件会触发检测，改走内存补丁或一并处理自校验。

## 五、网络型

1. 抓包确认端点：Burp / mitmproxy / Proxifier（对非代理感知程序用 Proxifier 强制走代理）。
2. 三条路径：
   - **hosts 重定向 + 本地 mock**：`C:\Windows\System32\drivers\etc\hosts` 指到 127.0.0.1，本地起同端口服务复刻响应（HTTPS 需自签证书并信任）。
   - **客户端 Hook**：Hook `WinHttpReadData` / `HttpSendRequest` / `recv` 改返回缓冲。
   - **DLL 劫持**：把自写 DLL 放进加载目录，转发原导出并改写关键函数（适合有固定依赖 DLL 的程序）。
3. mock 只在本地起，不向真实第三方服务发请求。

## 六、试用 / 时间型

- 状态位置：`reg query` 查 `HKCU\Software\<Vendor>`、程序目录的 `*.dat/.lic/.key`、`%APPDATA%` 下配置。
- 时间型：除清状态外，可 Hook `GetSystemTime` / `GetLocalTime` / `SystemTimeToFileTime` 冻结时间，或用调试器改返回值。
- 计数型：重置计数键，或把写入计数的调用 NOP 掉。
- 注意"时间回退检测"（记录上次启动时间，若变小则判定异常），需同时 patch 比较逻辑。

## 七、算法还原与 keygen

当校验是本地算法（A 类）时：

1. 在校验函数入口下断，取输入卡密与逐步运算。
2. 识别结构：长度校验 → 校验位/和 → 字符集映射（Base32 变形）→ 哈希比对（MD5/SHA1/CRC）→ 与机器码绑定。
3. 机器码绑定：找出机器码来源（卷序列号 / MAC / CPU ID / 用户名哈希），还原后 keygen 才能通用。
4. 用还原算法写生成器（Python），用**真实样本**验证生成的码能被接受；验证不通过就回去修算法，不要编造成功结果。

## 八、验证

- 改前备份：`copy target.exe target.exe.bak`
- 改后运行：断网一次、联网一次、清状态后再一次，三态都测。
- 贴真实命令行输出与程序表现；未跑的步骤标 `未执行` 并给出下一条命令。
