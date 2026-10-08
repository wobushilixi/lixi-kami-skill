# JSRPC：真实浏览器当"签名计算器"（Web 逆向保底打法）+ 三项定位技法

> 来源吸收：`Fausto-404/js-reverse-automation--skill`（590⭐，JSRPC+Flask+autoDecoder 方案）、
> `715494637/reverse-skill`（366⭐，写边界证明/请求链证据/检查点验证/交接文件）、
> `WhiteNightShadow/hello_js_reverse_skill`（1317⭐，Phase 0-5/经验库/任务级检查）。
>
> **本 Skill 的工具已就绪**：`scripts/jsrpc_server.py`（中继+CLI）+ `templates/jsrpc_client.js`（浏览器注入）。

---

## 一、JSRPC 方案（核心）：不还原算法，直接借浏览器的算力

**什么时候用**（命中任一即上，别死磕算法）：
- 签名算法涉及 JSVMP/私有 VM，静态还原成本失控
- 补环境反复失败（反复对不上真值）
- 只需要"能产出合法签名/密文"来重放、批量、mock、接 Burp——**不要求离线纯算**
- **约束检查**：用户明确要求"纯算法、不依赖浏览器"时**不适用**（交付物必须过 `js-signature-reverse.md` 的双闸门）

**架构**：页面注入客户端 → WebSocket 连本地中继 → 本地 CLI/脚本远程调用页面函数。

### 三步用法（本机实测通过）

```bash
# 1) 起中继（后台常驻）
python scripts/jsrpc_server.py serve --port 19090

# 2) 注入客户端：用 js-reverse-mcp / chrome-devtools 的 evaluate_script，
#    把 templates/jsrpc_client.js 全文作为函数体注入（(() => { ...内容... })()）
#    注入成功：返回值含 "[jsrpc] client injected"，服务端显示"浏览器已连接"

# 3) 调用（三选一）
python scripts/jsrpc_server.py eval "return window.anySignFn('a=1&b=2')"   # 任意 JS
python scripts/jsrpc_server.py call CryptoJS_AES__encrypt '["明文","密钥"]'  # 已暴露函数
python scripts/jsrpc_server.py list                                        # 看连接与暴露清单
```

**客户端内置能力**（注入后即可用）：
```js
__jsrpc.eval(code)                    // 任意 JS
__jsrpc.expose("sign", signFn)        // 暴露页面函数
__jsrpc.wrap("CryptoJS.AES", "encrypt")   // 包一层对象方法（原逻辑照常）
__jsrpc.wrapAll("CryptoJS")           // 扫一层对象全部函数
```
默认自动包装：页面里若有 `CryptoJS.AES`/`CryptoJS.MD5`/`JSEncrypt` 自动暴露。

### JSRPC 拿来干什么（下游衔接）

| 用途 | 做法 |
|---|---|
| 重放/批量请求 | Python 每发一单前 `eval` 调页面真实签名函数 → 拿到 sign → 拼请求 |
| mock server | mock 服务端用 JSRPC 生成客户端要求的密文参数 |
| Burp autoDecoder | 本地 Flask 转发到 JSRPC（原方案形态），拦截改包自动补签名 |
| 喂给算法还原 | 拿 JSRPC 做**输入/输出采样器**：固定输入批量取真值，反哺纯算实现验证 |
| 验证纯算实现 | 同一输入：JSRPC 真值 vs Node 复现值 → 逐字节比（检查点验证） |

**纪律**：
- 只连 `127.0.0.1`（工具已限定）；页面刷新后客户端掉线 → 重新注入（2 秒自动重连兜底）
- JSRPC 产物属于**运行时依赖**：交付"纯算法"任务时必须用自己的实现替换，JSRPC 只作对照真值
- 页面处于风控观察期时低频调用（它是真实会话，别把账号玩进风控）

---

## 二、写边界证明（找"谁写的"，而不是"叫什么名"）

**痛点**：搜 `sign`/`encrypt` 找不到函数——因为混淆后名字没了，而且值可能被多处改写。
**方法**：不找名字，找**写入点**。

```
1. 断在发送边界：XHR.send / fetch / WebSocket.send 的入参
2. 拿到目标字段的当前值 → 上溯：
   a. 值从对象里来的 → Object.defineProperty 追 setter；或在 Sources 里对该属性名全局搜赋值
   b. 值从函数返回的 → 在该调用点 step into（js-reverse-mcp 的 step）
3. 命中"唯一真实写入点"（real writer / builder / sink）才算定位完成
4. 记录证据：函数地址/文件:行 + 输入输出样本（进交接文件）
```

**判据**：改动该写入点的输出 → 请求里的字段随之变化（**因果验证**，不是"看起来像"）。

## 三、请求链证据模型（把"一个请求"升级为"一条链"）

对目标请求，逐项建立可复核证据：

| 证据项 | 内容 |
|---|---|
| 触发动作 | 用户在页面做了什么触发了它（点激活/输卡密/定时心跳） |
| 上游依赖 | 前置请求（预热/取 token/设备注册）与其返回值的消费点 |
| 状态消费 | 本请求返回值被谁消费（存 localStorage / 进后续请求头 / 驱动 UI） |
| 正常/风控分叉 | 正常响应 vs 风控/错误响应 的字段差异（**先制造一次正常 + 一次失败做对照**） |

这条链同时就是我们后续"改客户端判定"的落点清单（B/C 类必做）。

## 四、检查点验证（防止"看起来成功了"）

```
固定样本（inputs 记录存档）
  → 对齐三层：输入 / 输出 / 中间状态
  → 本地实现 vs 浏览器真值 逐项比对
  → 全部一致才算一个检查点通过；写进交接文件
```
- 输入必须**固定**（随机源钉死或直接用公开样本）
- 中间状态指：关键函数的入参/出参快照（用 JSRPC 顺手采样）

## 五、跨会话交接文件（抗上下文压缩）

Web 任务在工作目录维护 **`reverse-records/请求链路.md`**，包含：
1. 目标 URL / 接口 / 字段
2. 触发方式与已固定的样本
3. 请求链证据（上表五项）
4. 写边界结论（文件:行 + 因果验证结果）
5. 检查点状态（哪些已通过、哪些待验）
6. 当前判断 + 下一步 + 缺什么证据

**会话中断/压缩后**：新会话先读该文件 + 原任务提示词即可续跑（本 Skill 执行强化协议 §3 断点续跑的落地载体）。

## 六、任务级检查（借鉴 hello_js_reverse 的 preflight）

每个 web 任务开工前问四项，命中就先本地复检再继续：
- 浏览器/frame 环境变了吗（换了页面、iframe 嵌套）？
- 登录态变了吗（cookie/token 过期）？
- SDK/站点改版了吗（旧结论失效）？
- 新会话（上下文丢了）？→ 先读 `reverse-records/请求链路.md`。

## 七、与其它文档的衔接

| 需要 | 去哪 |
|---|---|
| 签名链五阶段（完整方法论） | `js-signature-reverse.md` |
| 失败症状直查表（13 种） | `web-reverse-failure-modes.md` |
| 加密原语识别（拿到疑似函数后） | `crypto-signature-playbook.md` |
| 侦察（HAR/目录/URL 三模式） | `scripts/web_recon.py` |
