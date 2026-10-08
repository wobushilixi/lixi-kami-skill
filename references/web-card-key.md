# Web 卡密验证逆向（S1–S4）

> 配套：**先跑** `python scripts/web_recon.py <har|目录|url>`（侦察）→ 卡住查 `web-reverse-failure-modes.md`（症状直查表）→ 签名链细节走 `js-signature-reverse.md`。

适用：网页版卡密/激活码验证系统、网页端会员校验、接口型网络验证、网页外挂/辅助的登录授权页。

## 一、先判形态（决定打哪一层）

| 形态 | 特征 | 主策略 |
|---|---|---|
| **纯前端校验** | 断网也能"验证通过"；卡密算法写在 JS 里 | 改 JS 判定 / 油猴脚本 / 直接看源码拿算法 |
| **前端判定 + 接口返回** | 接口返回 `code/msg/status`，前端 `if` 决定放行 | **改前端判定分支**（最稳） |
| **接口主导** | 每次都请求，断网直接失败；前端只渲染 | mock 响应 / 代理改包（响应有签名时无效，改前端渲染逻辑） |
| **WASM / 混淆** | JS 里只有胶水代码，核心在 `.wasm` 或 `_0x` 混淆 | 先反混淆；WASM 用 `wasm2wat` 看导出函数 |
| **第三方验证平台** | 域名像 `xxx-yanzheng.com`，参数是卡密 + 机器码 + sign | 见下方"网络验证通用模型" |

## 二、S1 分析

### 工具三板斧（DevTools）

1. **Network**：勾 Preserve log，输入错误卡密点一次，找验证请求 → 看 URL、请求参数、响应体字段。
2. **Sources**：全局搜 `kami / card / license / verify / activate / vip / expire / 卡密 / 激活`，或用 `Ctrl+Shift+F` 全站搜索。
3. **Application**：看 `localStorage` / `sessionStorage` / Cookie 里有没有 `vip`、`expire`、`token`、`license` 之类的键。

### 自动扫描

```bash
# 把网页另存为目录（或用浏览器插件导出全部 JS）后：
python scripts/web_kami_scan.py ./saved_site --top 15 --json work/web_scan.json

# 有 HAR 抓包时（DevTools → Network → 导出 HAR）：
python scripts/web_kami_scan.py capture.har --top 20
```

看这几组：**endpoint**（验证接口在哪）、**token**（用什么凭据）、**storage**（状态存在哪）、**crypto / obfuscate**（要不要先反混淆）。

### 关键判据：响应有没有服务端签名

- 请求里带 `sign` / `nonce` / `timestamp` → 有防篡改和防重放，**改包伪造响应基本无效**。
- 响应体只有 `{"code":0,"msg":"ok"}` 且能随便改 → 可以直接改包。
- 判不出来时，用 mitmproxy 改一次响应试试，看前端是否照单全收。

## 三、S2 方案（四类，按代价排序）

| 方案 | 做法 | 优势 | 代价 | 适用 |
|---|---|---|---|---|
| **A 改本地 JS 副本** | 把 JS 存到本地，改判定后浏览器加载本地副本 | 不需要任何插件/代理，最直观 | 只能自己用；页面更新后失效 | 纯前端、或前端判定 |
| **B Chrome Overrides** | DevTools → Sources → Overrides，直接覆盖线上 JS | 不用改服务端，刷新也生效 | 只在配了 Overrides 的浏览器里生效 | 前端判定 |
| **C 油猴脚本注入** | Tampermonkey 里改函数返回值 / 改 localStorage | 一次写好长期生效，可分享 | 需要装插件 | 前端判定、状态在前端 |
| **D 代理改响应** | mitmproxy / Charles 断点改响应体 | 不改任何前端代码 | 响应有签名时无效；要装证书 | 接口主导且响应无签名 |

**推荐顺序**：A/B（改前端判定）→ C（要长期生效）→ D（只在响应无签名时）。

## 四、S3 实施（可直接用的模板）

### A. 本地 JS 副本

```bash
# 1) 找到判定逻辑（典型形态）
#    if (resp.code === 0) { showVip() } else { showError('卡密无效') }
# 2) 改成无条件放行
#    if (true) { showVip() }
node --check modified.js      # S4：语法校验
python -m http.server 8080    # 本地起服务验证
```

### B. Chrome Overrides 步骤

1. DevTools → Sources → Overrides → 选一个本地文件夹 → 允许。
2. Network 里右键目标 JS → Save for overrides。
3. 直接在 Sources 里改，Ctrl+S 保存，刷新页面即生效。

### C. 油猴脚本模板

```javascript
// ==UserScript==
// @name         kami bypass
// @match        https://目标域名/*
// @run-at       document-start
// @grant        none
// ==/UserScript==
(function () {
  'use strict';
  // 1) 直接改状态存储（最简单，很多站点吃这套）
  const KEYS = ['vip', 'isVip', 'vipState', 'license', 'auth', 'expire', 'expireTime'];
  KEYS.forEach(k => {
    try { localStorage.setItem(k, '1'); } catch (e) {}
  });
  try {
    localStorage.setItem('expireTime', String(Date.now() + 3650 * 86400 * 1000));
  } catch (e) {}

  // 2) 改判定函数（把下面函数名的模式换成实际名字）
  const FORCE = ['isVip', 'checkAuth', 'checkKey', 'verifyCard', 'isValid', 'isExpired'];
  const wrap = (obj) => {
    if (!obj) return;
    for (const k of Object.keys(obj)) {
      const v = obj[k];
      if (typeof v !== 'function') continue;
      if (!FORCE.some(p => k.toLowerCase().includes(p.toLowerCase()))) continue;
      try {
        obj[k] = function () { return true; };     // 强制返回 true
        console.log('[kami] forced', k);
      } catch (e) {}
    }
  };
  wrap(window);

  // 3) 拦住接口响应（可选）
  const origFetch = window.fetch;
  window.fetch = function (...a) {
    return origFetch.apply(this, a).then(async r => {
      const url = (typeof a[0] === 'string') ? a[0] : (a[0] && a[0].url) || '';
      if (/verify|auth|license|card|key|vip|member/i.test(url)) {
        const txt = await r.clone().text();
        console.log('[kami] resp', url, txt.slice(0, 300));
      }
      return r;
    });
  };
})();
```

### D. mitmproxy 改响应（仅响应无签名时）

```python
# mitmproxy -s rewrite.py
from mitmproxy import http

def response(flow: http.HTTPFlow):
    if any(k in flow.request.pretty_url for k in ("verify", "auth", "license", "card", "vip")):
        try:
            body = flow.response.get_text()
            body = body.replace('"code":1', '"code":0').replace('"status":0', '"status":1')
            flow.response.set_text(body)
        except Exception:
            pass
```

### E. 本地 mock server（验证 B/C 类时用）

```python
from http.server import BaseHTTPRequestHandler, HTTPServer
import json

class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0))
        self.rfile.read(n)
        body = json.dumps({"code": 0, "msg": "ok", "status": 1,
                           "expire": "2099-12-31 23:59:59", "vip": 1}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        print("[mock]", self.path)

HTTPServer(('127.0.0.1', 8899), H).serve_forever()
```

配合 hosts 或改前端里的接口地址指向本地。

## 五、S4 测试（工程验证）

| 检查项 | 方法 |
|---|---|
| JS 语法 | `node --check modified.js` |
| 覆盖是否生效 | DevTools → Sources 看文件右上角是否标了 `.overrides`；console 打印日志 |
| 油猴是否注入 | 页面 console 出现 `[kami]` 日志 |
| mock 是否通 | `curl -X POST http://127.0.0.1:8899/verify -d '{}'` 返回预期 JSON |
| 判定点是否被执行到 | 在改的函数里加 `console.log`，看是否打印 |

## 六、真机实测（可选，真实浏览器）

**三态，缺一不可**：

1. **断网**（DevTools → Network → Offline）：还能不能进功能页
2. **联网**：正常访问，看服务端会不会把状态纠正回去（很多站点心跳会纠正）
3. **清状态**：`localStorage.clear()` + 清 Cookie，重新走一遍完整流程

每态贴真实输出：console 日志、Network 里验证接口的响应体、页面实际表现。

## 七、常见坑

| 现象 | 原因 | 处理 |
|---|---|---|
| 改了 JS 刷新又变回去 | 没用 Overrides，或走了缓存 | 用 Overrides；勾 Disable cache |
| 状态改了但一会又掉 | 心跳请求被服务端纠正 | 同时处理心跳：改本地时间判断或拦心跳响应 |
| 找不到验证逻辑 | 在 WASM / 异步加载的 JS 里 | `wasm2wat` 看导出；Network 里找后加载的 JS |
| JS 全是 `_0x` 乱码 | 混淆 | 用 deobfuscate 工具（如 js-beautify + 手工还原字符串表）；或放弃读逻辑，直接改渲染后的状态 |
| 改包没生效 | 响应有签名 / 前端验签 | 放弃改包，改前端判定分支 |
| HTTPS 抓不到 | 证书没装 / 证书绑定 | 装 mitmproxy 根证书；证书绑定只能改前端 |
| SPA 页面刷新后状态丢失 | 状态只存在内存 | 同时改 localStorage 里的持久化字段 |

## 八、边界

- 只对**用户自有 / 已授权**的页面做本地改写与 mock 验证。
- 不向真实第三方服务发起压测、爆破、批量请求；需要验证接口行为时用本地 mock。
- 客户端改写在服务端复核面前只对本机生效，报告中要如实说明这一边界。
