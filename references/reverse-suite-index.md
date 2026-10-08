# 逆向三件套接入索引：android-reverse / web-reverse / win-reverse

> 这三套框架已**安装为独立技能**（2026-10-08），本文件是「什么时候用哪套、怎么调、纪律怎么对齐」的唯一路由源。
> 原则与外部知识库一致：**不搬运内容**——本技能保留卡密/授权专项主线，通用逆向任务转交三套框架，按需读其 playbook。

## 一、安装位置与定位

| 技能 | 位置 | 定位 | 触发信号（摘要） |
|---|---|---|---|
| **android-reverse** (v3) | `C:\Users\Administrator\.zcode\skills\android-reverse` | APK/DEX/SO/JNI、加固脱壳、Frida、协议还原、设备指纹、OLLVM、Flutter/Hermes/Unity、Split、WebView、smali patch | APK/AAB/XAPK、DEX、SO/JNI、smali、脱壳、反调试、dex2so、Android CTF |
| **web-reverse** (v3) | `C:\Users\Administrator\.zcode\skills\web-reverse` | JS 签名/协议还原、混淆与反调试、JSVMP/WASM、扣代码、**补环境**、指纹、验证码/滑块 | sign/加密参数还原、混淆 JS、WASM、source map、补环境、Node 复现 |
| **win-reverse** (v2) | `C:\Users\Administrator\.zcode\skills\win-reverse` | PE/EXE/DLL/SYS/.NET、壳与 OEP/IAT、驱动、Frida、TLS/SSL Pinning、Loader/注入、Electron/CEF、游戏引擎(UE/Unity)、恶意样本 | DLL 注入、Manual Map、COM/RPC/ALPC、x64dbg、dnSpy、UE4/GNames、易语言 |

**与本技能（lixi-nixiang）的分工**：
- **卡密 / 激活码 / 授权链路**（含网页卡密、网络验证 SDK、嵌入式 payload 卡密）→ 走本技能 S0–S4 主流程。
- **通用逆向任务**（不涉及卡密，或卡密已解、需深挖 native/协议/保护）→ 转三套框架，用它们的 task-local 状态机。
- 交叉场景：卡密目标被强壳/反调试挡住 → 先转 android-reverse 处理壳与动态层，再回本技能继续卡密链路（或反之）。

## 二、调用方式（三套统一是「任务契约 + 状态机」）

```bash
# 首次（在项目目录内执行，产物落 <项目>/artifacts/tasks/<task-id>/）
node <技能路径>/tools/task/task-start.mjs <task-id>          # android / win
node <技能路径>/tools/task/task-boot.mjs  <task-id>          # web（boot = init+sync+advance）
# 续跑
node <技能路径>/tools/task/task-sync.mjs  <task-id>
node <技能路径>/tools/task/task-advance.mjs <task-id>        # 输出 nextExecutableAction，照着干
node <技能路径>/tools/task/task-record-attempt.mjs <task-id> --kind=probe --status=success --tool=... --strategy=... --evidence=... --hypothesis=... --expected=... --actual=...
node <技能路径>/tools/task/task-close.mjs <task-id>          # 收尾（web 侧另有 verify-once/assert-can-reply 门禁）
```

硬约束（实测验证过的行为）：
- **同一 workspace 只允许一个 task-local**；再建要 `--force-new-task`（冒烟测试确认过此门禁生效）。
- 产物必须落 `artifacts/tasks/<task-id>/`（web 侧有机械门禁，散落根目录会被 BLOCK/自动 relocate）。
- 完成声明前必须跑验证脚本（wire 到 `fixtures.json` + `verify-once`），**"脚本无报错 ≠ 完成"**。

## 三、纪律映射（本技能 ↔ 三套框架，避免双轨打架）

| 本技能（lixi-nixiang） | 三套框架 | 约定 |
|---|---|---|
| E# 假设台账（假设 + 依据 + 验证方式） | 假设债务 `assumptions.md`（OPEN/VERIFIED/INVALIDATED）+ 捷径声明 `[捷径]` | 同一任务内**用卡密流程时以 E# 为准，转交框架后以框架为准**；两套都要求"未验证不得当结论" |
| DoD 七项 + 双审（Standards/Spec） | 完成门禁（completionCriteria 逐条取证、claimLevel、acceptance-ready） | 结论口径一致：证据不足只能标"未验证/acceptance-ready" |
| 止损线（连续 2 次无证据失败回 S1；同层 3 处无效换层） | 停损（同方法连续 3 次失败 EXHAUSTED；同疑点 3 次上限；retrospective 后必须换**不同类**方法） | 取**更严**的一条执行 |
| S4 收口（补丁字节复核 + 产物自检 + 逻辑自证 + 行为级差分） | 阶段 D 验证（必须实测证据：截图/命令输出/x64dbg 断点） | 通用逆向任务必须过框架的验证门禁，不得只用静态自证 |
| 失败台账 F1–F10 | 各框架的过程记录（attempt-ledger / route-state） | 卡密任务记 F 台账；通用任务记框架 ledger，F 台账记一行指向它 |
| 证据落盘（cases/<目标>/） | `run/` + `state/`（fixtures.json 为硬证据真源） | 各按各的目录，交付报告里写清路径 |

**高价值纪律（三套共有，直接吸收进本技能执行习惯）**：
1. **先调查后实现**：没有调查产物不写补丁代码（win：阶段 A 无 investigation.md 不进 B）。
2. **Hook 是实现手段，不是调查手段**：不理解验证链就写 hook = 循环试错。
3. **历史结论只是假设**：上次会话的"发现"进 assumptions（OPEN），本会话实测后才算证据。
4. **算法自检 vs 服务端验收双闸门**（web）：随机源钉死后逐字节相等 = 算法对；服务端稳定接受 = 验收过。签名含随机/时间戳时，**别用朴素字节比对当验收**。
5. **浏览器 MCP 锁定**：多浏览器工具混用 = 指纹变化丢会话（Web 风控任务必须锁一个）。

## 四、按信号路由（摘要，细则读各框架 SKILL.md 的专题路由表）

| 信号 | 去哪 |
|---|---|
| 加固壳 / 动态 Dex / libDexHelper（梆梆） | android-reverse：`dex-loader-playbook.md` + `unpack-tool-matrix.md` |
| JNI / RegisterNatives 边界 | android-reverse：`jni-bridge-playbook.md`（先建桥再深挖 native） |
| SO 运行期自解密 / 匿名 RX | android-reverse：`so-runtime-evidence-playbook.md` |
| OLLVM（FLA/BR/BCF/SUB） | android-reverse：`signal-gates.md` + `deobfuscation-playbook.md` |
| 签名参数 / 请求风控字段 | web-reverse：`signature` 专题 + 本技能 `js-signature-reverse.md` |
| 混淆 JS / 字符串数组 | web-reverse：`deob-ob` 工具链 + `string-array-deobfuscation-playbook.md` |
| 扣代码 / 最小闭包 | web-reverse：`closure-extraction-playbook.md` |
| **补环境跑不动（Node ↔ 浏览器差异）** | web-reverse：`env-conformance-playbook.md` + `env-drift-decision-tree.md` |
| JSVMP / WASM / 媒体解密 | web-reverse：`vmp-playbook.md`（总入口）→ 按需 WASM/DRM 分册 |
| 验证码 / 滑块 / 点选 | web-reverse：`captcha-slider-playbook.md` + `scripts/captcha/*` |
| PE 壳 / OEP / IAT 重建 | win-reverse：`packers.md`、`static-triage-playbook.md` |
| .NET / Mixed-Mode（C++/CLI） | win-reverse：`dotnet.md`、`mixed-mode-interop-playbook.md` |
| 驱动 / IOCTL | win-reverse：`driver.md` |
| 注入 / Manual Map / Process Hollowing | win-reverse：`loader-injection.md` |
| Electron / CEF / WebView2 套壳 | win-reverse：`electron-playbook.md`、`web-shell-triage.md` |
| 游戏引擎（UE4/UE5/Unity/IL2CPP） | win-reverse：`game-reverse.md`；Unity APK 侧用本技能 `unity-il2cpp.md` |
| 恶意样本 / 勒索 / RAT | win-reverse：`malware-analysis.md` |

## 五、成熟度与边界（如实引用，不夸大）

- 三套框架自带 topic 成熟度分级（`synthetic-e2e` / `guided` / `closed-loop`）：**成熟度 = 模板与 QA 深度，不等于真实目标已验证**（原文口径）。遇到 `guided` 级主题（如 android 的 vmp-analysis、so-runtime-evidence）按"需要人工判断更多"对待。
- win-reverse 明示：**历史失败案例**（Typora 激活案：脚本无报错 ≠ 完成，未截图就报进展 → 被证伪）。这条教训与本技能「禁止未验证即交付」同源，作为反面教材保留。
- 三套框架均要求中文输出、中文报告（代码/标识符除外），与本技能一致。
