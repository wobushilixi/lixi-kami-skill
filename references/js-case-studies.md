# JS/Web 逆向实战案例索引（可复用的成品代码）

> 三个**已跑通的真实案例**，2026-10-08 从 `F:\破解and逆向分析\skill开发\相关代码.zip` 落地到
> `C:\Users\Administrator\tools\reverse-cases\`。**不搬运进 skill 仓库**（单个案例 83MB），
> 按需读取；本文件是索引 + 提炼的技法要点。

## 案例一：腾讯防水墙文字点选验证码**纯算**（无浏览器 / 无 Node）

位置：`C:\Users\Administrator\tools\reverse-cases\tencent-tdc-captcha\`（11 个 Python 文件，104KB）
目标站点：bigmodel.cn（智谱开放平台）；依赖：仅 `requests` + 本地 OCR。

**完整链路（8 步，可照搬的骨架）**：
```
1. cap_union_prehandle        → 拿 sess / pow_cfg / dyn_show_info / tdc_path
2. 下载 tdc.js                → 静态提取 XTEA 密钥 + 运行时偏移 + eks token
3. 下载验证码背景图
4. 本地 OCR                   → 汉字归一化坐标
5. 构造鼠标轨迹（trajectory.py）
6. 构建并加密 collect         → VM 的 XTEA-ECB 变体
7. MD5 前缀 PoW 求解（pow_solver.py）
8. POST cap_union_new_verify  → 提交
```

**最有价值的部分（技法提炼）**：
- **VM 字节码静态还原三件套**：`tdc_loader.py`（解析 JS 提取字节码模块）→ `disassembler2.py`（反汇编）→ `opcode_mapper2.py`（操作码映射）→ `key_extractor2.py`（从反汇编结果里抠出 XTEA 密钥与偏移）。**这套「JSVMP → 字节码 → 反汇编 → 抠密钥」流程可直接套用到其他 VM 混淆目标**（对应 web-reverse 的 `vmp-playbook.md`）。
- **PoW 是独立可解环节**：MD5 前缀碰撞，`pow_solver.py` 单独成模块 —— 遇到验证码/挑战先查有没有 PoW 前置。
- **轨迹仿真**：`trajectory.py` 生成轨迹而不是随机点 —— 轨迹形态是被风控校验的特征。
- 这是「**模式 E 纯算法提取**」的完整范例：最终产物零浏览器依赖。

## 案例二：TikTok Web 签名 X-Bogus / X-Gnarly

位置：`C:\Users\Administrator\tools\reverse-cases\tiktok-x-bogus\`（1.3MB）
含：`node_harness.js`（补环境骨架）、`biz.common.lib.js`（业务库片段）、`async_57651.js`（异步模块）、Python 包 `TikTokWebSign`（算法移植成品）。

**用法（Python 侧最终产物形态）**：
```python
from TikTokWebSign import TikTokWebSign
sigs = TikTokWebSign.sign(query_string, include_bogus=True)
# → {'xGnarly': ..., 'xBogus': ...}
```

**技法提炼**：
- **`node_harness.js` 是补环境的参考模板**：把浏览器里的加密函数扣到 Node 后缺什么补什么（对应 web-reverse `env-patching.md` 与 `env-conformance-playbook.md`）。
- **签名输入是 query string 的规范化形式**：`sign(query)` 直接吃 URL 参数串 —— 抖音/TikTok 系签名的通用形态：`参数串 → 哈希/字节混淆 → 定长签名`。
- **Python 包形态交付**（`pip install TikTokWebSign`）：跨语言交付的样板（对应本技能「T 5 本地迁移」的交付形态）。

## 案例三：抖音搜索 a_bogus 纯 Node 复现（**web-reverse 框架实战范例**）

位置：`C:\Users\Administrator\tools\reverse-cases\douyin-abogus\`（83MB，4366 文件）

目标：`www.douyin.com/aweme/v1/web/discover/search/`，要求在**纯 Node**（无 jsdom、无浏览器页面取值）下本地实时生成 `a_bogus` + `msToken` + `uifid/webid`。

**为什么价值最高**：它是 web-reverse 框架**完整跑完一遍的产物**，带全部过程记录：
```
artifacts/tasks/douyin-search-node-sign/
├── task.json / core-task.json     # 任务契约（objective/交付梯度/completionCriteria）
├── report.md                      # 最终报告（含"当前方案的真实边界"章节）
├── run/                           # 硬证据：fixtures、capture_*.js、trace JSON
├── state/                         # clues / route-state / narrative（四段叙事）
├── archive/run_archive_*/         # 归档：cookie 事实、canvas 指纹、成功请求样本
└── local/                         # 成品本地复现代码
```
可直接当**模板**学：任务契约怎么填、证据怎么落盘（`browser_abogus_trace.json` / `browser_success_search_request.json` / `canvas_c1.txt`）、报告怎么写"真实状态"（已跑通什么、边界在哪）。

**技法提炼**：
- **预热链是必须的**：`/web/common` → `/web/r/token` → 搜索接口。**只抄签名函数不做预热 = 请求被风控拒**（这是抖音系签名的通用形态）。
- **动态 msToken**：msToken 不是静态值，要走 token 接口实时取（对应 `browser_token_truth.json` / `browser_token_nwid_template.json`）。
- **canvas 指纹参与环境**：`canvas_c1.txt` / `canvas_c2.txt` 被采集为环境输入 —— 补环境时这些"看似无关"的值可能是签名的输入之一（对应 web-reverse `env-as-algorithm-input-playbook.md`）。
- 报告明确写了**脱敏**（cookie/会话令牌/指纹快照已移除）—— 案例复用时注意自己也要做同等脱敏。

## 怎么用这三个案例（与本技能/三套框架的衔接）

| 你的场景 | 读哪个 | 对应 playbook |
|---|---|---|
| 遇到 JSVMP/字节码混淆抠密钥 | 案例一 `tdc_loader/disassembler2/opcode_mapper2/key_extractor2` | web-reverse `vmp-playbook.md` |
| 验证码/挑战链（点选/滑块） | 案例一全流程 + web-reverse `captcha-slider-playbook.md` | 本技能 `js-signature-reverse.md` §挑战链 |
| 扣代码到 Node 跑不通 | 案例二 `node_harness.js` | web-reverse `env-patching.md` |
| 签名参数（X-Bogus/a_bogus 类） | 案例二/三 | 本技能 `js-signature-reverse.md` |
| 想要"框架正确用法"的完整样板 | 案例三 `artifacts/tasks/` 全套 | web-reverse `SKILL.md` 红线与门禁 |
| 跨语言交付（Node→Python 包） | 案例二 `TikTokWebSign` | 本技能交付形态参考 |

**纪律提醒**：案例里含真实站点接口名与历史样本数据 —— **只做方法参考，不直接对案例中的真实站点发起请求**；要验证自己改的算法，用本地 mock 或你自己的授权目标。
