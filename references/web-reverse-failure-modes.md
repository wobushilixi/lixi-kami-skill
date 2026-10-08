# Web 逆向失败模式与对策（成功率诊断手册）

> **为什么 web 逆向成功率低**：不是工具不够，是**卡点没被识别**。同一个"打不开/拿不到/跑不通"
> 背后有十几种完全不同原因，用错对策就白烧时间。本表按「症状 → 根因 → 对策」直查。
>
> 配套：`scripts/web_recon.py`（先侦察）→ 本手册（对症下药）→ `js-signature-reverse.md` / `web-card-key.md`（执行）。

---

## 0. 战前顺序（把成功率从"碰运气"变成"流程"）

```
1. 先要 HAR       ← 静态路线比 live 路线稳；没有 HAR 才走浏览器
2. web_recon.py   ← 接口分类 + 参数分类 + JS 排名 + 路由建议（30 秒）
3. 按 §1 查表     ← 对照症状选对策，不要瞎试
4. 有 sign → js-signature-reverse 五阶段；有密文 → crypto-signature-playbook 速查
5. 改判定不改响应  ← 响应带签名/加密时的唯一稳路
```

## 1. 症状速查表（先查这里）

| # | 症状 | 根因 | 对策（按成本排序） |
|---|---|---|---|
| 1 | 页面要过 Cloudflare/WAF，或无限验证码 | 风控拦机器流量 | ① `stealth-browser-mcp`（反检测浏览器，97 工具）② 人工浏览器操作 + 导出 HAR ③ 降频（别连续请求） |
| 2 | 打开 F12 页面就卡死/跳转/清屏 | DevTools 检测 | ① **不开 DevTools 窗口**：用 `js-reverse-mcp` 的 CDP 层断点（`break_on_xhr`/`set_breakpoint_on_text`）② 本地副本先 patch 检测函数（`debugger`/`devtools` 重写为空函数）③ 纯 HAR+静态路线 |
| 3 | HAR 里没有业务请求，只有静态资源 | SPA 懒加载 / 没触发目标动作 | ① **先在页面里实际操作**（输卡密→点激活）再导出 HAR ② Sources → XHR/fetch 断点看 initiator |
| 4 | 搜 `sign`/`encrypt` 找不到签名函数 | 签名藏在别处 | ① `web_recon.py` 的 JS 排名（评分高者优先）② `get_request_initiator` 从请求回溯调用链 ③ 查 Worker/WASM/iframe（web_recon 会标） |
| 5 | Node 里跑签名函数报错/结果不对 | **补环境失败**（最高频） | ① `tools/reverse-cases/tiktok-x-bogus/node_harness.js` 模板 ② 钉死随机源（Math.random/Date.now 固定值）③ canvas/webgl/navigator 从真实浏览器 dump 后回填 ④ web-reverse 框架 `env-conformance-playbook.md` |
| 6 | 参数是长密文，找不到 key | 加密在库函数里 | ① **hook 库函数拿明文**：`CryptoJS.AES.encrypt` 断点看入参（key/iv/明文直接落手里）② 国密/自研 → `crypto-signature-playbook.md` 原语速查 |
| 7 | 改了响应没用 / 重放失败 | 响应有签名 / 一次性 nonce | ① **别伪造响应** → 改「客户端解析后的判定分支」② nonce/time 窗 → 本地复现 sign 函数生成新签名 |
| 8 | 验证接口要登录态 | 登录墙 | ① 让用户提供测试账号 / 已登录的 HAR ② HAR 重放带 Cookie（`session`/`token` 在请求头里） |
| 9 | 改完客户端一会儿又失效 | B/C 类心跳纠正 | ① 改解析判定 + 本地缓存（`network-sdk-fingerprints.md` §二 五个打点）② 心跳失败路径一并改成"保持有效" |
| 10 | 签名逻辑在 `.wasm` / Worker 里 | 特殊运行时 | ① WASM：**黑盒调用优先**（导出函数直接喂参数，别反编译）② Worker：在主线程 hook `postMessage` 收发 ③ web-reverse 框架对应 playbook |
| 11 | HAR 几百条请求，噪声淹没 | CDN/SDK 第三方域名 | `web_recon.py` 接口分类自动过滤 STATIC；按域名分桶（借鉴 third_party_hosts denylist 思路） |
| 12 | JS 几百个 chunk，无从下手 | webpack 分包 | `web_recon.py` 排名 → 只给前 3 名做反混淆/扣代码；别的不管 |
| 13 | 验证弹窗在 iframe 里 | 跨域嵌套 | 定位 iframe 的 src 源站 → 单独对那个站跑 web_recon（独立目标） |

## 2. 三个最高频卡点的展开

### 2.1 补环境失败（症状 5）——先固定三个源头

```js
// node_harness 里先钉死随机/时间（否则每次输出不同，永远对不上）
Math.random = () => 0.123456789;
Date.now = () => 1786000000000;
performance.now = () => 12345.678;
// canvas 指纹：从真实浏览器执行 toDataURL 拿真值，硬编码回填
// navigator/webgl：按需补，但"能跑通的最小集"优先（少补多验）
```
**验证顺序**：同输入两次跑 → 输出一致（随机已钉死）→ 与浏览器 hook 到的真值逐字节比 → 才敢说还原成功。

### 2.2 签名函数定位（症状 4）——从请求往回走，别从代码往前搜

```
web_recon.py 排名 → 第 1 名文件里搜 XHR/fetch 调用点
→ js-reverse-mcp: get_request_initiator(请求) 拿调用链
→ set_breakpoint_on_text 断在参数组装处 → step 进签名函数
→ 拿入参/出参对照（这就是 hook 观测法，见 crypto-signature-playbook §一）
```

### 2.3 风控拦截（症状 1）——换工具而不是硬刚

无头/自动化特征被识别 → 换 `stealth-browser-mcp`（nodriver 真实浏览器实例）；
仍被拦 → **人工接管**：用户用自己的浏览器操作到目标页，导出 HAR，我们走静态路线。
**不要**在风控上反复重试（风控会加重标记——止损线适用）。

## 3. 成功率自检（每次 web 任务过一遍）

| # | 检查 | 没做会怎样 |
|---|---|---|
| 1 | 拿到 HAR 了吗（或在页面里实际操作过）？ | SPA 场景全靠猜 |
| 2 | 跑过 `web_recon.py` 了吗？ | 不知道看哪个 JS、哪个参数是签名 |
| 3 | 签名参数识别了吗（sign类/密文类/固定值）？ | 走错路线（该扣代码的去 mock） |
| 4 | 补环境前钉死随机源了吗？ | 输出永远对不上，白折腾 |
| 5 | 响应有签名吗？（有 → 绝不伪造，改判定） | 改包全无效 |
| 6 | 失败 2 次后换对策了吗（对照 §1 换行）？ | 在同一卡点烧光预算 |

## 4. 与其它文档的衔接

| 场景 | 去哪 |
|---|---|
| 签名链五阶段 / 断点三板斧 | `js-signature-reverse.md` |
| 卡密链路四种打法（Overrides/油猴/mock/改判定） | `web-card-key.md` |
| 加密原语识别（SPECK/SM3/ARX/RC4 变体…） | `crypto-signature-playbook.md` |
| 三个真实案例（含补环境模板、JSVMP 还原） | `js-case-studies.md` |
| 环境补不上 / 浏览器 MCP 选择 | web-reverse 框架 `env-conformance-playbook.md` / `browser-mcp-capability-map.md` |
