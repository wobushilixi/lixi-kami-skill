# MCP 逆向工具链：安装状态、注册方式、能力映射

> **2026-10-08 v2（大升级）**：IDA Pro 9.3 / JEB 5.30.1 / Cheat Engine 7.7 / jadx-gui 全部就位，
> MCP 从"能握手"升级为"**已端到端验证**"（真实目标上跑通工具调用）。
> **纪律：注册前先握手验证（initialize + tools/list）；声称可用前必须在真实目标上调用一次工具。**

## 一、状态总表（✅=已注册且实测通过）

| MCP | 状态 | 工具数 | 前置（已全部安装） | 关键能力 |
|---|---|---|---|---|
| **idalib-mcp** ⭐ | ✅ **实测通过** | **65** | IDA Pro 9.3 + idapro wheel + idalib 激活 | **无头 IDA：decompile/disasm/xrefs/list_funcs/find_bytes…**——不开 GUI 就能反编译（真实目标 `libcardverify.so` 已成功反编译出 C 代码） |
| **ida-pro-mcp** | ✅ 已注册 | （同上 65） | IDA GUI 运行 + 插件 | GUI 模式：配合 IDA 界面用 |
| **jadx-mcp** ⭐ | ✅ **实测通过** | **32** | jadx-gui 1.5.5 运行 + jadx-ai-mcp 插件 | 反编译浏览、`get_android_manifest`（真实返回 6.0.apk 的 manifest）、类/方法检索、smali |
| **jeb-mcp** | ✅ **握手通过** | **14** | JEB 5.30.1 运行 + MCP.py 插件 | 反编译、manifest、调用者/覆盖关系（JEB 强在 ARM/混淆） |
| **cheatengine-mcp** ⭐ | ✅ **握手通过** | **175** | CE 7.7 运行（Lua 桥已入 autorun） | **内存读写/扫描/指针链/RTTI/断点**——游戏与内存逆向主力 |
| **stealth-browser-mcp** | ✅ 实测通过 | **97** | 独立 venv | 反检测浏览（Cloudflare/风控绕过） |
| **js-reverse-mcp** | ✅ 实测通过 | 24 | npx | `get_request_initiator`/`break_on_xhr`/`step`（签名逆向） |
| **chrome-devtools-mcp** | ✅ 实测通过 | 30 | npx | 页面操作、网络、console |
| node_repl | 内置 | — | — | （非逆向用） |

**当前注册总数 9 个**（8 个逆向相关 + node_repl），配置在 `~/.zcode/cli/config.json` 的 `mcp.servers`（每次改动前已自动备份 `.bak-时间戳`）。

## 二、安装位置速查（2026-10-08 全部落地）

| 工具 | 路径 | 备注 |
|---|---|---|
| **IDA Pro 9.3** | `C:\Program Files\IDA Professional 9.3` | KG 补丁已应用（ida.dll/ida32.dll 已换，原版备份 `.orig.bak`）；许可证在 `%APPDATA%\Hex-Rays\IDA Pro\idapro.hexlic` + 安装目录各一份 |
| IDAPython | Python **3.12.13**（uv 管理） | 用 `idapyswitch --force-path <python3.dll>` 指定；3.14 不行会崩 |
| idalib | `ida-config.json` 的 `ida-install-dir` 已设 | `py-activate-idalib.py` + `idapro-0.0.7` wheel 装入 uv venv |
| ida-pro-mcp / idalib-mcp | `tools\mcp\ida-pro-mcp-main_x\ida-pro-mcp-main`（uv venv） | 插件已装 `%APPDATA%\Hex-Rays\IDA Pro\plugins\ida_mcp.py` |
| **JEB 5.30.1** | `C:\Users\Administrator\tools\jeb`（1.1GB） | 已授权（Super-Black Edition，perpetual）；CLI：`jeb_wincon.bat -c …`；需要 Java 17+（系统 JDK21） |
| jeb-mcp | `tools\mcp\jebmcp_x\jebmcp`（uv venv） | 插件已装 `%APPDATA%\JEB\plugins\MCP.py` + `scripts\MCP.py`；服务端口 16161 |
| **Cheat Engine 7.7** | `C:\Users\Administrator\tools\cheatengine\Cheat Engine` | Lua 桥 `ce_mcp_bridge.lua` 已放 **autorun/**（CE 启动自动加载） |
| CE MCP bridge | `tools\mcp\cheatengine-mcp-bridge-main_x`（uv venv） | Named Pipe `CE_MCP_Bridge_v99` |
| **jadx-gui 1.5.5** | `C:\Users\Administrator\tools\jadx-gui`（`jadx-gui-launch.bat` 启动，官方 exe 启动器不可用） | 插件用 `java -jar lib\jadx-gui-1.5.5-all.jar plugins -j <jar>` **正式安装**（落 `%APPDATA%\skylot\jadx\plugins\installed`） |
| jadx-mcp-server | `tools\mcp\jadx-mcp-server-6.4.0_x` | 全局 Python 3.14 + fastmcp 4.0.11 已装 |
| **雷电模拟器 14**（去广告+面具+LSPosed） | `D:\LDPlayer14\雷电模拟器14-v14.0.7.7-去广告绿色版\LDPlayer14` | 绿色版（Bandizip SFX 解压）；`dnplayer.exe` 主程序、`ldconsole.exe` CLI、`adb.exe` |
| Android 工具 APK | `C:\Users\Administrator\tools\apks\` | BlackDex64_3.2.3（脱壳）/ MT管理器_2.26.4（去签/编辑）/ 开发助手_9.0.0 |
| ApkCheckPack | `C:\Users\Administrator\tools\apkcheck\ApkCheckPack.exe` | `-f <APK>` 壳特征检测 |
| VSCode 扩展 | Claude Code ✅ 已装；ChatGPT ❌（vsix 损坏 + 市场不通，待重下） | — |

## 三、启动与联调（可复制）

```bash
# --- idalib（无头，推荐；无需任何 GUI）---
cd C:\Users\Administrator\tools\mcp\ida-pro-mcp-main_x\ida-pro-mcp-main
uv run idalib-mcp --stdio            # MCP：开新库用 idb_open(input_path=...)
# 直接 Python（跳过 MCP，脚本化）：
uv run python -c "import idapro; rc=idapro.open_database(r'X.so', run_auto_analysis=False); print(rc)"

# --- jadx（需 GUI 常驻）---
C:\Users\Administrator\tools\jadx-gui\jadx-gui-launch.bat <目标.apk>   # 等 8650 端口 LISTENING 后 jadx-mcp 即可用
netstat -ano | findstr :8650

# --- JEB（需 GUI 常驻；插件随 JEB 启动监听 16161）---
C:\Users\Administrator\tools\jeb\jeb_wincon.bat                      # 启动 GUI
C:\Users\Administrator\tools\jeb\jeb_wincon.bat -c --license         # 验证授权

# --- Cheat Engine（需 GUI 常驻；Lua 桥 autorun 自动加载）---
"C:\Users\Administrator\tools\cheatengine\Cheat Engine\Cheat Engine.exe"   # 建议管理员运行

# --- 雷电模拟器（Android 动态环境）---
LD="D:\LDPlayer14\雷电模拟器14-v14.0.7.7-去广告绿色版\LDPlayer14"
"$LD/ldconsole.exe" list2              # 看实例（0=雷电模拟器 已配置）
"$LD/ldconsole.exe" launch --index 0   # 启动模拟器
"$LD/adb.exe" install -r C:\Users\Administrator\tools\apks\BlackDex64_3.2.3.apk
```

## 四、能力映射（语义层 → 具体工具）

| 需求 | 首选 | 备选 |
|---|---|---|
| **无头反编译/反汇编 so/ELF/PE** | `idalib-mcp`（decompile/disasm） | JEB、objdump |
| 查 xref / 找字符串引用 | idalib-mcp（xrefs_to/search_text/find_bytes） | IDA GUI |
| APK Java 层全景 | `jadx-mcp`（get_package_tree/get_class_source） | apktool+smali |
| APK manifest/组件 | jadx-mcp（get_android_manifest/get_manifest_component） | aapt2 |
| **内存读写/扫描/指针链** | `cheatengine-mcp`（read_memory/scan_all/analyze_pointer_access） | x64dbg |
| ARM/重型混淆反编译 | `jeb-mcp` | IDA+Hex-Rays |
| Web 签名/断点 | `js-reverse-mcp` | chrome-devtools |
| 被风控拦截的网页 | `stealth-browser-mcp` | — |
| **Android 动态分析环境** | 雷电14（自带面具+LSPosed）+ BlackDex/MT | 真机 |
| APK 壳特征 | ApkCheckPack | packer_detect.py |

**锁定纪律（承接 web-reverse）**：一个任务锁一个浏览器 MCP，混用=换指纹=丢会话。

## 五、实装踩坑记录（都是我踩过的，照抄结论）

1. **IDA 官方静默安装参数失效**：`--mode unattended` 直接 exit 1（GUI 模式正常）。**解决：写 optionfile**（`mode=unattended\nprefix=...`）用 `--optionfile opt.txt` 启动。
2. **IDA 许可证文件名是关键**：9.3 按 **`idapro*.hexlic`** 通配搜索（不是 `ida.hexlic`）。放 `%APPDATA%\Hex-Rays\IDA Pro\`；放错名字的表现是"License not yet accepted"→"Cannot continue without a valid license"两级报错。
3. **IDA 补丁判据**：原版 ida.dll 只有 `EDFD425CF978`，补丁版同偏移换成 `EDFD42CBF978`（keygen.js 里 cModulus 开头）。备份 `.orig.bak` 必须做。
4. **IDAPython 版本**：3.14 不可用（idapyswitch 里选 3.12/3.10）。装完必须跑 `ida.exe -A -S"脚本.py"` 验证 `IDAPython 64-bit v9.3.0`。
5. **jadx 插件目录是三层**：`%APPDATA%\skylot\jadx\plugins\{installed,dropins}\`（只放 `plugins\` 根下**不会加载**）。正解：`java -jar jadx-gui-all.jar plugins -j <插件.jar>` 正式安装；验证 = 启动后 `netstat` 看 **8650 LISTENING**。
6. **jadx-gui 官方 exe 启动器不可用**（静默退出 code 0）→ 用 `javaw -jar lib\jadx-gui-1.5.5-all.jar`（已封成 jadx-gui-launch.bat）。
7. **fastmcp 版本冲突必须分 venv**：jadx-mcp-server 要 ≥3（全局 4.0.11），stealth-browser-mcp 钉 2.11.2 → 各自独立 venv，绝不混装。
8. **CE 设置项**：`编辑→设置→附加→取消"查询内存区域例程"`（防止 DBVM/保护页下 CLOCK_WATCHDOG 蓝屏）——GUI 手动一次。
9. **Program Files 写入需提权**：本会话是非提权 token；对本机 UAC=静默自动提权（ConsentPromptBehaviorAdmin=0），用 `Start-Process -Verb RunAs` 跑提权 PS 脚本即可。
10. **F 盘 exe 不能直接执行**（且 requireAdministrator 的 exe 在 bash 下报 "Permission denied"）→ 先 `cp` 到本地盘，再用 PowerShell RunAs 或 `cmd /c`。
11. **大文件下载**：GitHub 直连不稳时走本地代理 `socks5h://127.0.0.1:10808` + `-C -` 续传；下载完先 `zipfile.testzip()` 校验再解压（曾拿到 45MB 假 zip）。
12. **雷电是 Bandizip SFX**：`7z x -p000000 <安装器.exe>` 直接解出绿色版（无安装器，密码就是 000000）。
