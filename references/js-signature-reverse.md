# JS 前端签名链逆向（Web 卡密 / 接口验证专用）

> 配套升级：**写边界证明**（找「谁写的」而非「叫什么名」）、**请求链证据**、**检查点验证**、**JSRPC 保底路线**、跨会话交接文件 —— 见 `jsrpc-browser-oracle.md`。

> 来源：融合 haikow/claude-reverse-skills 的 mcp-js-reverse-playbook 五阶段方法 + 实战经验。
> 适用：接口签名（sign/nonce/timestamp）、加密参数、风控字段、前端校验绕过。
> 原则：**Observe-first（先观察）→ Capture（最小采样）→ Rebuild（本地复现）→ Patch（按报错补环境）→ DeepDive（去混淆，仅必要时）**

## 0. 五阶段总览

| 阶段 | 目标 | 出口标准 |
|---|---|---|
| 1 Observe | 确认目标请求、相关脚本、候选函数，**不猜环境** | 目标 URL 特征 + initiator 线索 + 可疑脚本清单 |
| 2 Capture | 最小侵入采样：参数样例、调用顺序、运行时证据 | 同一请求 3 次采样的参数差异表（固定/变化字段） |
| 3 Rebuild | 把页面证据整理成 Node 可迭代复现材料 | 本地脚本能复现"发出同样请求" |
| 4 Patch | 按报错和 first divergence 补环境直到跑出目标参数 | 稳定产出与页面一致的签名值 |
| 5 DeepDive | 去混淆、控制流还原、算法提纯 | 只要出签名可降级；长期复用必须做 |

## 1. Observe：签名链定位（从请求往回找）

```text
DevTools → Network → 找到目标请求 → Initiator 列（调用来源）
  ├─ 有 initiator → 点开直接跳到发起代码行
  ├─ 无 initiator（编程式触发）→ XHR/fetch 断点：输入 URL 片段断下
  └─ 被拦截器包裹 → 搜 axios.interceptors / fetch 重写 / XMLHttpRequest.open
```

**搜什么（按命中率排序）**：

| 关键词 | 命中含义 |
|---|---|
| `sign` / `signature` / `sig` | 签名字段本体 |
| `nonce` / `timestamp` / `ts` | 防重放参数（每次变化 → 采样对比确认） |
| `JSON.stringify` + `sort` | 参数排序后拼接（签名前必经） |
| `md5` / `sha256` / `hmac` / `CryptoJS` | 哈希算法 |
| `AES` / `DES` / `encrypt` | 加密参数 |
| `secretKey` / `appKey` / `salt` / `keyCode` | 密钥常量（**最值钱的发现**） |
| `_0x` / `atob(` / `eval(` | 混淆特征 |
| `localStorage.getItem` + `token` | 本地票据读取 |

**固定/变化字段判别法**（Capture 核心动作）：
- 同一操作连续发 3 次请求，逐字段对比：变的 = nonce/ts/随机数；不变的 = 固定 key/设备指纹
- 变化字段往前找赋值点，就是生成函数；固定字段搜字符串常量直接定位 salt

## 2. 断点三板斧（优先级从高到低）

1. **XHR/fetch 断点**：`Sources → XHR Breakpoints` 输入接口路径片段，命中后沿 Call Stack 往上找参数构造点
2. **运行时轻量观察**：Console 里直接调可疑函数（先 `typeof fn === 'function'` 确认），传样例参数看输出是否等于抓包值
3. **代码行断点（最后手段）**：定位到行再断，避免在压缩代码里乱断

命中后必看：**Call Stack（完整调用链）+ Scope（局部变量里的中间值）**。中间值（排序后的拼接串、md5 前的原文）比最终签名更有定位价值。

## 3. Rebuild：本地 Node 复现

- 先复制目标函数体 + 它依赖的常量/工具函数到本地 `.js`
- 用抓包到的真实参数跑一遍，**输出必须与抓包签名一致**才算复现成功
- 不一致 → 缺依赖或环境差异 → 进入 Patch

**禁止空想式补环境**：只补页面证据已证明需要的对象（报错 ReferenceError 指什么补什么），一次补一个最小因果单元，每次补丁后立即复测并确认报错是否前移。

典型补环境顺序：先补值（`navigator.userAgent` 等常量）→ 再补函数壳（`document.createElement` 返回空对象）→ 最后补返回对象契约（属性读取要什么返回什么）。

## 4. 常见前端签名方案速查

| 方案 | 特征 | 还原方法 |
|---|---|---|
| 参数排序 + `key1v1key2v2...+secret` → md5 | sign 固定 32 位 hex | 找拼接顺序和 secret 即出（搜 sort+concat） |
| body + timestamp + secret → HMAC-SHA256 → base64 | 44 位 base64 | 同上，注意 body 序列化格式必须逐字节一致 |
| AES 加密整个 body | 请求体是密文 | key/iv 通常硬编码或首包协商；搜 CryptoJS.AES |
| 自研魔改哈希 | 无标准库特征 | DeepDive：把函数抠出来本地跑，黑盒测输入输出 |
| WASM 计算签名 | `.wasm` 加载 + `WebAssembly.instantiate` | `wasm2wat` 转文本读逻辑，或直接 Node 加载 wasm 调用（**能黑盒调用就不白盒还原**） |
| 环境指纹参与签名 | sign 与设备相关 | 补环境阶段固定指纹值即可稳定复现 |

**黄金法则：能黑盒调用就不白盒还原**——函数抠出来能跑就别读算法；wasm 能加载就别反编译。

## 5. 卡密场景落地（对接 web-card-key）

| 卡密链路环节 | 签名逆向的用法 |
|---|---|
| 前端校验卡密格式 | 直接改 JS 判定分支（Overrides / 油猴），不需要签名 |
| 卡密验证接口带 sign | 还原签名算法 → 可**离线构造任意卡密的验证请求**做协议测试；或改客户端判定分支 |
| 激活接口返回加密票据 | 拿到解密 key 后能看懂票据结构 → 配合 mock/响应替换 |
| 防重放拦截重放包 | 从签名算法反推 nonce 生成规则，构造新鲜请求 |

## 6. 回退路径（fallbacks）

- 混淆太重读不懂 → 只抓运行时证据（断点 + Scope 中间值），放弃静态读
- 补环境循环报错 >10 次 → 停止，改走**浏览器内直接调用**（在目标页面 Console 里反复调用目标函数，自动化用油猴脚本）
- WASM 复杂 → 不还原，Node/浏览器黑盒调用出参表，找规律
- 接口有服务端校验无法伪造 → 回到 B/C 类架构策略：patch 客户端解析响应后的判定分支（最稳）

## 7. 证据纪律

- 每个结论附证据：截图 / HAR / 函数地址（脚本 URL:行号）
- 未跑通复现前不写"签名已还原"
- 本地复现输出与真实抓包**逐字节比对**通过才算 Rebuild 完成
