# 外部知识库索引

> **路径占位符说明**：本文中的 `$ROOT_KB` / `$REVERSE_KB` / `$REVERSE_SKILL_DIR` 是占位符，请替换为你本机实际路径；没有对应资料时该节忽略即可。

本 Skill 自带的是**方法与流程**；两个本地知识库是**深度资料**，按需查阅，不要重复搬运内容。

## 一、F:\知识库\Root知识库（Android Root 全生态，75 篇 / 4.5 万行）

适用：**外挂 / 游戏辅助 / 带环境检测的 App**。卡密绕过之后能不能跑起来，靠这里。

| 目录 | 什么时候查 | 代表文件 |
|---|---|---|
| `01-Root框架底层原理` | 选 Root 方案、理解注入点 | Magisk / KernelSU / APatch 架构解析、三大框架对比选型 |
| `02-模块开发实战` | 写 Magisk / Zygisk 模块 | 模块结构拆解、module.prop、跨框架兼容 |
| `03-隐藏与反检测技术` | **过 Root 检测**（最常用） | 应用层/系统层 Root 检测大全、风险环境检测、PlayIntegrity、SUSFS、银行与游戏绕过案例 |
| `04-进程管理与保活` | 注入与 Hook 原理 | 进程注入与 Hook 技术、进程隐藏与伪装 |
| `06-源码深度分析` | 需要源码级确认 | ZygiskNext、Shamiko、TrickyStore、PlayIntegrityFix、LSPosed 源码分析 |
| `07-检测与对抗模块` | **过检测工具**（Momo / Ruru / Hunter） | 各工具检测原理与对抗、ACE 最新检测变化 |
| `08-实战案例` | 要照抄完整流程 | 王者荣耀 / 三角洲 / CF / 银行 App 隐藏全流程 |
| `11-拓展专题` | Bootloader 解锁、LSPosed 模块开发、SELinux | 05-LSPosed 与 Xposed 模块开发入门 |
| `12-ACE对抗专题` | **腾讯系手游外挂**（用户主场景） | ACE SDK 检测项逐项修复、网络层对抗边界、模拟器对抗、一键配置清单 |

检索方法（全文带 YAML frontmatter，用 keywords 字段最快）：

```bash
grep -rn "keywords" "F:/知识库/Root知识库" | grep -iE "隐藏|检测|root|模拟器|ACE"
# 或直接找标题
find "F:/知识库/Root知识库" -name "*隐藏*"
```

入口文件：`00-AI导航.md`（意图路由表 + 版本基线 + 术语别名）—— **AI 调用前先读它**。

## 二、F:\知识库\逆向知识库（渗透与逆向，381 文件：198 md + 181 py）

适用：**分析方法、工具脚本、Web 与二进制分析**。

| 目录 | 对本 Skill 的用途 |
|---|---|
| `逆向分析类/加壳与脱壳` | S1 脱壳（每个目录含 `SKILL.md` + `scripts/script.py`） |
| `逆向分析类/混淆还原` | S1 代码混淆（ProGuard / OLLVM / 控制流平坦化）还原 |
| `逆向分析类/密码算法识别` | S1/S3 识别卡密算法用的哈希与加密（对应 A 类 keygen） |
| `逆向分析类/运行时Hook与注入` | S3 Hook 方案（本 Skill 默认静态，需要时用） |
| `逆向分析类/静态分析`、`PE文件分析`、`ELF文件分析` | S1 Windows / native 分析 |
| `逆向分析类/密码算法识别` | 卡密算法识别 |
| `移动端攻击类/APK静态分析` | S1 APK 分析流程 |
| `移动端攻击类/App动态调试`、`移动流量分析与抓包` | S1/S4 动态与抓包 |
| `移动端攻击类/移动数据存储泄露` | S1 找本地缓存的卡密状态（SharedPreferences / SQLite） |
| `Web攻击类/JWT攻击`、`API攻击` | **Web 卡密**：token / JWT 伪造、接口验证 |
| `Web攻击类/XSS与前端攻击` | Web 前端判定改写 |
| `爆破类-口令哈希破解` | A 类卡密若用弱算法时的离线验证（谨慎，仅本地） |
| `方法论框架类/渗透测试流程`、`报告模板与撰写` | 交付报告结构 |

脚本可直接调用（不必复制进 Skill）：

```bash
ls "F:/知识库/逆向知识库/逆向分析类/加壳与脱壳/scripts/"
# 需要时直接 python 运行，或读 script.py 看用法
```

## 三、F:\破解and逆向分析\reverse-skill（538 文件的逆向/安全 skill 集合）

本机已有这套包，**不复制内容，按需路由**。

| 入口 | 用途 |
|---|---|
| `RULES_zh.md` | **行为规范总纲**：激活与同意门、触发关键词、路由入口、**任务完成硬性 Checklist**、**Anti-Laziness 借口反驳表**、任务完成自检 |
| `README_AI.md` | AI 引导与部署路由（含 consent-gated 设置流程） |
| `skills/MASTER-ROUTING.md` + `skills/INDEX.md` | 全部专项 skill 的总路由表 |
| `skills/<name>/SKILL.md` | 专项：apk-reverse、ida-reverse、ghidra-reverse、binary-ninja-reverse、dotnet-reverse、firmware-pentest、binary-diff、ctf-sandbox、field-journal、case-review、browser-automation、cloud-k8s、database-security… |
| `scripts/`、`kali/`、`burp-mcp-full/`、`plugins/` | 工具脚本、渗透环境、Burp MCP、插件 |

用法：先读 `skills/MASTER-ROUTING.md` 找对应专项 skill → 再读该专项的 `SKILL.md`；需要工具清单时跑 `skills/scripts/refresh-tool-index.ps1`（Windows）或 `.sh`（Linux/Kali）生成本机 `tool-index.md`。

**与本 Skill 的分工**：卡密/授权验证链路走 lixi-nixiang-skill（S1–S4）；通用逆向与渗透专项、需要特定工具链时走 reverse-skill 的对应专项 skill。

## 四、haikow/claude-reverse-skills（GitHub，MIT，已提炼入库）

`https://github.com/haikow/claude-reverse-skills`——Claude Code 逆向 skill 集合（reverse-engineering / apk-reverse / ida-reverse / radare2 / mcp-js-reverse-playbook）。**核心干货已提炼进本 Skill 的两个 reference，不必再回读原库**：

- `references/js-signature-reverse.md` ← mcp-js-reverse-playbook 的五阶段方法（Observe→Capture→Rebuild→Patch→DeepDive）
- `references/binary-quickwins.md` ← reverse-engineering 的 field-notes/patterns（Quick Wins 漏斗、诱饵目标、比较方向、内存 dump、算法常量速查、特殊格式路线、radare2 速查）

需要更深的 CTF 专案模式（patterns-ctf 1-3、VMProtect/Themida、Ghidra 高级脚本）时本地克隆在 `F:\破解and逆向分析\work\claude-reverse-skills`，按需读 `skills/reverse-engineering/*.md`。

## 五、incogbyte/android-reverse-engineering-claude-skill（GitHub，APK 动态自动化）

`https://github.com/incogbyte/android-reverse-engineering-claude-skill`——APK 自动化逆向：端点提取（Retrofit/OkHttp/Volley/GraphQL/WebSocket）、调用链追踪（Activity→ViewModel→Repository→网络）、自适应绕过循环（静态发现→生成定向脚本→吃 crash log 迭代）。本 Skill 已覆盖其静态 patch 主线（crash-troubleshooting.md 的二分法回溯即其自适应循环的静态版）；做**接口端点批量提取**时可参考其思路：全局搜 `@POST|@GET|OkHttpClient|newCall|enqueue` + URL 正则。

## 六、mattpocock/skills（工程方法论来源，非逆向内容）

`https://github.com/mattpocock/skills`（MIT，27 个技能）是**面向软件工程**的 Agent 技能库：TDD、领域建模、code review、grilling 访谈、spec/tickets，**不含逆向内容**。因此不整体搬入，只提炼 4 条可迁移纪律（严格诊断循环、交付双审、先问清再动手、对照实验），已写入 `references/engineering-discipline.md` 并落进 S1–S4 与交付自检。

需要完整方法论时可安装：`claude plugins install mattpocock-skills` 或 `npx skills@latest add mattpocock/skills`——对本 Skill 只需那四条纪律，逆向主战场仍是本 Skill 的 references 与 scripts。

## 七、与本 Skill 阶段的对应

| 阶段 | 本 Skill 用什么 | 不够时查哪 |
|---|---|---|
| S1 分析 | `packer_detect.py` / `kami_scan.py` / `web_kami_scan.py` | 逆向知识库（加壳脱壳、混淆还原、密码算法识别）；Root 库 03/07（是否带环境检测）；binary-quickwins.md（格式速查） |
| S2 方案 | `packer-analysis.md` 报告模板 | Root 库 08 实战案例；逆向库 方法论框架类 |
| S3 逆向 | `smali_kami_patch.py` / `elf_patch.py` 系列 / `xposed_kami_module.java` | 逆向库 运行时Hook与注入；binary-quickwins.md（patch 速查/内存 dump）；haikow 库 patterns*.md（CTF 级手法） |
| S3 Web 签名 | `js-signature-reverse.md` 五阶段 | 逆向库 Web攻击类/JWT攻击、API攻击 |
| S4 测试 | 回编 / 签名 / mock | 逆向库 移动流量分析与抓包 |
| 可选：真机实测 | 三态验证 | **Root 库 03/12**（环境隐藏与自检清单）；逆向库 App动态调试 |

## 七点五、2026-10-08 外部新发现（已吸收要点，仓库本身按需访问）

> 本节为「主动联网搜索外部逆向 skill」的成果。**没有找到公开的"卡密破解/keygen"专项 skill**——
> 该细分基本处于私有状态，本 Skill 的卡密链路覆盖仍是自有优势。以下为可借鉴的邻居：

| 资源 | 是什么 | 已吸收到什么 |
|---|---|---|
| `zhaoxuya520/reverse-skill`（GitHub，⭐4 万+，持续更新） | 本机 `F:\破解and逆向分析\reverse-skill` 的在线版：逆向/渗透路由包（Claude Code/Kiro/Cursor/Cline） | **Agent 借口反驳表（15+ 条）** → `execution-enforcement.md` §7；**上下文布局规则** → §5b；完成自检 → 已融合进 DoD |
| `yasminefolo/reverse-engineering-is-over` | 抖音 38.1.0 native 签名库案例研究（7 参数还原 6 个，30 天/$100） | **动态优先原则 + 逐参数攻坚 + 双轨验证 + 加密原语速查表** → `crypto-signature-playbook.md`（新） |
| `SimoneAvogadro/android-reverse-engineering-skill` | Android 逆向 skill（Phase0 分诊→API 提取→Kotlin 名称还原） | **Kotlin `@Metadata.d2` 名称还原术** → `scripts/kotlin_name_recovery.py`（新，R8 对抗）；Phase0 分诊思路已在 S0/S1 |
| `P4nda0s/reverse-skills` | Claude Code 逆向技能包：rev-symbol / rev-struct / rev-frida / rev-unicorn-debug / rev-dex-dumper / rev-u3d-dump / rev-idapython / rev-ios-dump | 与既有能力对照：rev-unicorn-debug≈`emu_check.py`、rev-idapython≈`idalib_probe.py`、rev-dex-dumper 思路已见 `unpack-repack.md`；**rev-struct（结构体还原）暂缺**——遇到结构体密集目标时按需装（`npx skills add P4nda0s/reverse-skills`） |
| `sector-b79/Malware-And-Reverse-Engineering-Skill-for-AI-Agents` | 跨助手（Claude/Codex/Gemini）恶意分析 skill | 证据清单（hash/strings/imports/流量/文件系统/注册表/进程/持久化）+ "观测事实与假设分开"——与 E# 纪律一致，已在我们文档中覆盖 |
| `SimoneAvogadro` 的 `third_party_hosts.txt` | 第三方域名 denylist（用于 host 分桶） | 方法记入：接口分析先按域名分桶，过滤 CDN/SDK 噪声 |

**使用方式**：要点已提炼进本 Skill，不必回读原仓库；需要更深的（如 rev-struct）再按需安装/访问。

---

## 八、使用原则

1. **不搬运**：知识库内容不复制进 Skill，只在需要时读取并引用路径。
2. **先本地后外部**：Skill 自带脚本能解决的先跑脚本，不足再查知识库。
3. **引用要具体**：报告里写清结论来自哪个文件（路径 + 章节），便于复核。
4. **版本敏感**：Root 生态版本迭代快，涉及模块版本时以知识库 `00-AI导航.md` 的版本基线为准。
