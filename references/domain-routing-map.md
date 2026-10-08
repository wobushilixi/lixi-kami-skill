# 邻域地形图与厂商检索清单（融合自 r0crawl_skills）

> 用途：卡密链路常常不在「纯客户端卡密」这一个盒子里——它可能压在**风控 SDK、验证码、
> WAF、VMP、协议自研**之上。本文件把 r0crawl_skills 的路由地形图压缩成**检索清单**，
> 并映射到本 Skill 自己的资产；命中什么信号，就先查哪一条线。
>
> **使用纪律**：本文件是**检索线索**，不是结论。厂商会改版，下列名称/参数仅供在目标页面
> 抓包时快速对号；**任何指纹命中都必须用目标自身的证据（请求、cookie、脚本）复核**，
> 禁止把清单直接当判定（违反 SKILL.md「禁令二：禁止盲试」）。

---

## 一、跨域信号 → 先查什么

| 信号 | 本 Skill 资产（优先） | 邻域检索点（r0crawl 模块名 / 通用线） |
|---|---|---|
| APK 壳 / 加固 / ClassLoader / dlopen | `unpack-repack.md`、`packer-analysis.md`、`s0/s1` 脚本 | `apk-protection-analysis`、`constructor-dlopen-tracing`、`apk-classloader-tracing` |
| DEX 内存 dump / 修复 / 重载验证 | `unpack-repack.md`（BlackDex → NP 修复） | `dex-memory-dump`、`dexfixer-reconstruction`、`memdumper-artifact-validation` |
| SO / ELF / 符号 / 结构恢复 | `elf-binary-card-key.md`、`apk-embedded-binary-cardkey.md` | `native-binary-analysis`、`symbol-recovery-and-structs`、`function-boundary-recovery` |
| 反调试 / 完整性 / 反注入 | `anti-defense.md`、`crash-troubleshooting.md` | `anti-analysis-and-integrity`、`debugger-bypass-analysis`、`crc-integrity-analysis` |
| Root / 模拟器 / 环境检测 | `android-env-detection.md` | `root-emulator-detection` |
| Frida 被检测 / Hook 痕迹 | （本 Skill 默认静态，动态走 `mcp-toolchain.md`） | `frida-anti-detection-analysis`、`anti-hook-artifact-analysis`、`stealth-hook-methodology` |
| TLS Pinning / 抓不到包 | `android-env-detection.md`、`web-reverse-failure-modes.md` | `tls-pinning-analysis`、`android-network-stack` |
| JS 签名 / token / 密文参数 | `js-signature-reverse.md`、`web_recon.py`、`jsrpc-browser-oracle.md` | `web-signature-analysis`、`crypto-dataflow-analysis`、`reconstruction-and-parity` |
| JS 混淆 / webpack / AST | `js-case-studies.md`、`binary-quickwins.md` | `js-deobfuscation`、`ast-program-analysis`、`obfuscator-io-analysis`、`webpack-vite-nextjs-reversing` |
| **JSVMP / VMP / 字节码 VM** | `crypto-signature-playbook.md`（静态被击败时切动态） | `jsvmp-vmp-analysis`、`virtualization-protection`、`script-vm-sandbox-analysis` |
| WASM 加密 / 签名 | `web-reverse-failure-modes.md`（WASM-Worker 卡点） | `wasm-reversing`、`wasm-crypto-signature` |
| Worker / iframe / ServiceWorker | `web-reverse-failure-modes.md` | `js-worker-hooking`、`browser-runtime-tracing` |
| 浏览器补环境 / 指纹 | `jsrpc-browser-oracle.md` | `browser-env-emulation`、`browser-fingerprint-analysis` |
| 验证码 / 挑战 / WAF / 403 / 412 | `web-reverse-failure-modes.md`（13 种失败模式） | `captcha-protocol-analysis`、`anti-bot-analysis` |
| PCAP / 私有协议 / 心跳 | `network-sdk-fingerprints.md`（网络验证 SDK） | `protocol-reconstruction`、`websocket-grpc-analysis`、`protobuf-schema-recovery` |
| 自定义编码 / 已知明文推导 | **`known-plaintext-derivation.md` + `derive_block_solver.py`** | `ctf-key-recovery`、`kctf-*` 系列、`reconstruction-and-parity` |
| 加密原语识别（XTEA/RC4变体/SM4/CRC） | `crypto-signature-playbook.md`（常量定位法） | `crypto-dataflow-analysis`、`runtime-crypto-boundary` |
| 崩溃 / 补丁后闪退 | `crash-troubleshooting.md` | `native-crash-signal-attribution`、`crash-dump-symbolication` |
| 脱壳产物 / 补丁产物验收 | `verify_patch.py`、`s4_pipeline.py`、`unicorn-emu.md` | `build-artifact-reproducibility`、`reverse-artifact-manifest`、`reverse-validation-checklists` |
| 通用编排 / 建案 / 报告 | **`evidence-case-conventions.md`** | `reverse-case-orchestration`、`evidence-collection`、`reverse-reporting-and-attribution` |

---

## 二、风控 / 验证码 / WAF 厂商检索清单

抓包后先对号；**命中即按厂商专项路线走，不要从零设计**。名称仅为检索线索。

| 厂商 | 检索线索（cookie / 参数 / 脚本） | 备注 |
|---|---|---|
| Akamai | `_abck`、`bm_sz`、`ak_bmsc`、`sensor_data` | 请求体带 sensor_data 时重点看 |
| Cloudflare | `cf_clearance`、`__cf_bm`、Turnstile 挑战页 | 失败模式见 `web-reverse-failure-modes.md` |
| AWS WAF | `aws-waf-token` | |
| Imperva / Incapsula | `visid_incap*`、`incap_ses*`、`reese84` | |
| DataDome | `datadome` cookie | |
| PerimeterX / HUMAN | `_px*`（`_pxhd`、`_px3`） | |
| Kasada | `x-kpsdk-*` 请求头 | |
| 瑞数信息 | 动态 cookie + 首次响应内嵌 JS 自解 | 每次响应变化，别硬编码 |
| 阿里系（TMD/NVC/AWSC/Baxia） | `_____tmd_____`、`nvc`、`awsc` 相关参数 | 电商/云盾场景 |
| 京东 | `jcap`、H5ST 相关参数 | |
| 极验 Geetest | `gt`、`challenge`、`w` 参数、`geetest_*` | 点选/滑块 |
| 腾讯 TCaptcha | `t.captcha.qq.com`、`TencentCaptcha` | 防水墙 |
| 网易易盾 | `dun.163.com`、`NECaptchaValidate` | |
| 顶象 / 数美 | 请求内 `dx-*` / `smid` 类设备标识 | 名称需以抓包复核 |
| Google reCAPTCHA | `g-recaptcha-response` | |
| hCaptcha | `h-captcha-response` | |
| Yandex SmartCaptcha | `smart-captcha` | |

### 站点级签名参数（公开资料密集，拿来当检索词）

抖音 `a_bogus` / `x-bogus`｜小红书 `x-s` / `x-t`｜淘宝 MTOP `H5ST` / `sign`｜美团
`mtgsig`｜知乎 `zse`｜雪球 `acw` / `md5__1038`｜百度翻译 `sign`｜有道 `sign`｜
B 站 / 微博 / 网易登录风控参数。命中后走 `js-signature-reverse.md` 五阶段，不要直接抄公开实现。

---

## 三、移动端「加载链」检索清单（脱壳/so 必过一遍）

按时间线问自己：
1. 什么触发了保护（`attachBaseContext` / `Application` 替换 / `dlopen` / JNI_OnLoad）？
2. 关键代码在 **APK 内、内存映射、还是运行时解密后**？ → 决定 dump 还是静态
3. 有没有**匿名可执行内存**（RX 段）→ 常见于 VMP/壳的解密载荷
4. dump 出来的产物能否被**消费工具**打开（jadx / IDA）？打不开就先修（`dexfixer-reconstruction` 思路）
5. 产物有没有 **manifest + SHA256 + 来源地址**？（见 `evidence-case-conventions.md`）

---

## 四、关于已安装的 r0crawl-skills（诚实审计结论）

已安装为独立 Skill：`~/.zcode/skills/r0crawl_skills/`（`git pull` 即可更新）。

**审计事实（2026-10-08 实测）**：
- 仓库声明 218 个专项模块，但其中 **170 个模块正文是同一份通用模板**（只有标题不同，
  即「名字壳」）；**46 个模块有独有正文**，价值集中在 KCTF 2026 题解与少数专项。
- `references/` 565 行，多为索引；`examples/` 10 个 4 行速览；`scripts/` 19 个脚本
  均可用但极简（3–21 行）。其中 `derive_solver.py` 的 `try_params()` 是
  `NotImplementedError` 空实现，本 Skill 已用 `derive_block_solver.py` 补齐并实测通过。

**因此正确用法**：
- **当检索词表用**：它的模块名/路由表能提醒你「这条线存在」（即本文件第一、二节的来源）；
- **深挖具体模块时先看正文是否模板**：模板 = 无内容，别浪费时间读；
- **真货优先读**：`kctf-*` 系列、`ctf-key-recovery`、`kanxue-kctf-workflow`、`*-checklists`、
  `python-frozen-app-reversing`、`cpython-runtime-introspection`。
