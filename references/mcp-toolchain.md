# MCP 逆向工具链：安装状态、注册方式、能力映射

> 2026-10-08 从 `F:\破解and逆向分析\skill开发\mcp.zip` 落地。**16 个 MCP 服务器**统一放在
> `C:\Users\Administrator\tools\mcp\`；已注册进 ZCode（`~/.zcode/cli/config.json` 的 `mcp.servers`）的只有验证过能跑的那几个。
> **纪律：注册前先握手验证（initialize + tools/list），不许"配置了就假定能用"。**

## 一、安装/注册状态总表

| MCP | 位置 | 状态 | 前置条件 | 关键能力 |
|---|---|---|---|---|
| **chrome-devtools-mcp** | npx（自动拉取）| ✅ **已注册·已验证**（v1.10.1，30 工具） | Node ≥20、Chrome | 页面操作、`evaluate_script`、网络请求列表、console、性能审计 |
| **js-reverse-mcp** | npx（自动拉取）| ✅ **已注册·已验证**（v4.0.5，24 工具） | Node ≥20、Chrome | **`get_request_initiator`、`break_on_xhr`、`set_breakpoint_on_text`、`step`、`get_script_source`、`search_in_sources`** —— 签名逆向主力 |
| **jadx-mcp** | `tools/mcp/jadx-mcp-server-6.4.0_x/` | ✅ **已注册**（依赖已装：fastmcp 4.0.11/httpx/requests；需运行 JADX-GUI + 插件） | JADX-GUI 1.5.x + `jadx-ai-mcp-6.4.0.jar` 插件（监听 8650） | 反编译浏览、类/方法检索、跨引用 |
| **stealth-browser-mcp** | `tools/mcp/stealth-browser-mcp-master_x/` | ⚠️ 独立 venv 安装中（`stealth-venv`，见安装日志） | nodriver + Chrome；**fastmcp==2.11.2 与全局 4.x 冲突，必须独立 venv** | 反检测浏览（Cloudflare/风控绕过），web 任务 Chrome 被拦时用 |
| ida-pro-mcp | `tools/mcp/ida-pro-mcp-main_x/` | ⚠️ 待 IDA | **IDA Pro 8.3+（Free 不支持）** + uv（本机已有） | IDA 内 RPC：反编译、xref、重命名、打补丁 |
| idalib-mcp | `tools/mcp/start-idalib-mcp.bat` | ⚠️ 待 IDA | IDA + idalib 授权 | **无头模式**（官方推荐替代 GUI 插件） |
| jebmcp / jebmcp2 | `tools/mcp/jebmcp_x/`、`jebmcp2-main_x/` | ⚠️ 待 JEB | JEB Pro（`start_jeb_mcp.bat`） | JEB 反编译（Android/ARM 强） |
| x64dbg-mcp | `tools/mcp/x64dbg-mcp_x/` | ⚠️ 待 x64dbg | x64dbg（插件形式，x32/x64 两份） | Windows 调试自动化 |
| cheatengine-mcp-bridge | `tools/mcp/cheatengine-mcp-bridge-main_x/` | ⚠️ 待 Cheat Engine | CE GUI | 内存扫描/修改自动化 |
| chrome-devtools / GUILessBingSearch | `tools/mcp/GUILessBingSearch-MCP_x/` | ⚠️ 依赖 PySide6 | Bing 搜索无 GUI 化（web 逆向搜索取证） | 外部情报检索 |
| 安装指南（4 份） | `tools/mcp/*.md` | ✅ 已落地 | — | ida-pro/jadx/js-reverse/idalib 的完整安装步骤（本文件是摘要，细节读原文） |

## 二、已验证 MCP 的复现命令（要复核时跑）

```bash
# 通用握手探针（initialize → tools/list）
python <你的工作目录>/mcp_probe.py --cmd cmd --arg=/c --arg=npx --arg=-y --arg=chrome-devtools-mcp@latest --timeout 120
# 或用纯 bash 管道（等价于 MCP 客户端行为）
JSON='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"p","version":"1"}}}'
(echo "$JSON"; sleep 6; echo '{"jsonrpc":"2.0","method":"notifications/initialized"}'; sleep 1; \
 echo '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'; sleep 6) | npx -y js-reverse-mcp
```
**2026-10-08 实测结果**：chrome-devtools-mcp → `chrome_devtools 1.10.1`，30 工具；
js-reverse-mcp → `js-reverse 4.0.5`，24 工具（含 `get_request_initiator` / `break_on_xhr` / `step`）。

## 三、能力映射（web-reverse 语义层 → 具体 MCP 工具）

| 逆向需要的语义动作 | js-reverse-mcp | chrome-devtools-mcp |
|---|---|---|
| 找参数生成调用链 | **`get_request_initiator`** | `get_network_request` |
| 断在签名函数上 | **`set_breakpoint_on_text` / `break_on_xhr`** | —（用 evaluate_script 退化） |
| 单步/看帧 | **`step` / `get_paused_info`** | — |
| 读/改脚本源码 | **`get_script_source` / `save_script_source` / `search_in_sources`** | — |
| 快速取值/试验 | `evaluate_script` | `evaluate_script` |
| 反检测（Chrome 被拦） | — | — （切 **stealth-browser-mcp**） |

**锁定纪律（承接 web-reverse 的 browser MCP pinning）**：一个任务锁一个浏览器 MCP，混用=换指纹=丢会话。
给了 `--cloak`/stealth 场景就用 stealth-browser-mcp 一锁到底。

## 四、按目标类型的最小工具集

| 目标 | 必备 | 增强 |
|---|---|---|
| Web 签名/风控字段 | js-reverse-mcp（断点+initiator） | chrome-devtools-mcp（网络/console）、stealth（被风控拦时） |
| Android APK | jadx-mcp（+JADX-GUI）、android-reverse 技能自带脚本 | ida-pro/idalib（native so）、jebmcp（强混淆） |
| Windows EXE | ida-pro-mcp 或 idalib-mcp | x64dbg-mcp（动态）、cheatengine（内存） |
| 卡密/授权专项 | 本技能 scripts/（packer_detect/kami_scan/elf_patch/emu_check/s4_pipeline） | 按需叠加上述 |

## 五、注意与坑（实测记录）

- **Windows 下 npx 必须 `cmd /c npx ...`**（ZCode 配置里已按此写法）；Git Bash 里手测时用 `//c` 或 MSYS_NO_PATHCONV=1。
- **fastmcp 版本冲突是真实坑**：jadx-mcp-server 要 ≥3.0.2（本机全局 4.0.11），stealth-browser-mcp 钉死 2.11.2 → **必须分 venv，绝不能装进同一个环境**。
- **`initialize` 是唯一可信的"能跑"判据**：`npx xxx --help` 没输出不代表坏（js-reverse-mcp 就是无 --help 的正常态）。
- 下载大包（jadx 69MB 带 JRE）在直连断流时走本地代理 `socks5h://127.0.0.1:10808`，支持 `-C -` 续传。
- 未装前置的 MCP（IDA/JEB/x64dbg/CE）**不要注册**——配置存在但握手失败会污染每个会话，宁可留文档。
