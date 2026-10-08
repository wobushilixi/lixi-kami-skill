/* jsrpc_client.js - 浏览器端 RPC 客户端（注入页面后，本地 Python 可远程调用页面函数）
 *
 * 注入方式（任选）：
 *   1) js-reverse-mcp / chrome-devtools 的 evaluate_script：
 *      把本文件内容整段作为函数体注入 —— (() => { <本文件内容> })()
 *   2) 浏览器控制台直接粘贴
 *
 * 注入后：
 *   - 自动连接 ws://127.0.0.1:PORT（默认 19090）
 *   - 暴露 __jsrpc 工具对象给页面
 *   - 本地即可：python scripts/jsrpc_server.py eval "return window.xxx('a=1')"
 *
 * 内置：eval / expose / wrap / wrapAll / exposed，断线自动重连。
 */
(() => {
  const PORT = window.__JSRPC_PORT || 19090;
  const WS_URL = `ws://127.0.0.1:${PORT}`;

  const FN = {};           // 已暴露函数表
  let ws = null, ready = false;

  // ---------- 内置能力 ----------
  const api = {
    // 任意 JS：字符串是函数体，用 return 返回值；也接受 (()=>...)
    eval: (code) => {
      try {
        const f = new Function(String(code));
        return f();
      } catch (e) { throw new Error('eval error: ' + (e && e.message)); }
    },
    // 暴露页面已有函数
    expose: (name, fn) => {
      if (typeof fn !== 'function') throw new Error('expose 需要函数');
      FN[name] = fn;
      return name;
    },
    // 按路径包一层对象方法，如 wrap("CryptoJS.AES", "encrypt")
    wrap: (objPath, method) => {
      const obj = objPath.split('.').reduce((o, k) => (o ? o[k] : undefined), window);
      if (!obj || typeof obj[method] !== 'function') throw new Error('找不到 ' + objPath + '.' + method);
      const name = objPath.replace(/\./g, '_') + '__' + method;
      FN[name] = obj[method].bind(obj);
      return name;
    },
    // 扫一层对象的所有函数
    wrapAll: (objPath) => {
      const obj = objPath.split('.').reduce((o, k) => (o ? o[k] : undefined), window);
      if (!obj) throw new Error('找不到 ' + objPath);
      const out = [];
      for (const k of Object.keys(obj)) {
        try {
          if (typeof obj[k] === 'function') {
            FN[objPath.replace(/\./g, '_') + '__' + k] = obj[k].bind(obj);
            out.push(k);
          }
        } catch (e) {}
      }
      return out;
    },
    exposed: () => Object.keys(FN),
    // 便捷：直接按名称调用（本地 call 走这里）
    call: (name, args) => {
      const fn = FN[name];
      if (!fn) throw new Error('未暴露函数: ' + name + '（先 __jsrpc.expose/wrap）');
      return fn.apply(null, args || []);
    },
  };

  // 常用自动暴露（页面里有就包上，没有就跳过）
  try { if (window.CryptoJS && window.CryptoJS.AES) api.wrapAll('CryptoJS.AES'); } catch (e) {}
  try { if (window.CryptoJS && window.CryptoJS.MD5) api.expose('CryptoJS_MD5', window.CryptoJS.MD5); } catch (e) {}
  try { if (window.JSEncrypt) api.expose('JSEncrypt', window.JSEncrypt); } catch (e) {}

  window.__jsrpc = api;

  // ---------- 连接与消息循环 ----------
  function connect() {
    ws = new WebSocket(WS_URL);
    ws.onopen = () => {
      ready = true;
      ws.send(JSON.stringify({ type: 'hello', role: 'browser', exposed: Object.keys(FN) }));
      console.log('[jsrpc] connected, exposed:', Object.keys(FN));
    };
    ws.onmessage = async (ev) => {
      let msg;
      try { msg = JSON.parse(ev.data); } catch (e) { return; }
      if (msg.type !== 'call') return;
      const { id, fn, args } = msg;
      try {
        let result;
        if (fn === 'eval') {
          result = api.eval((args || [''])[0]);
        } else {
          result = api.call(fn, args);
        }
        // Promise 也支持
        if (result && typeof result.then === 'function') result = await result;
        ws.send(JSON.stringify({ type: 'result', id, ok: true, result: safe(result) }));
      } catch (e) {
        ws.send(JSON.stringify({ type: 'result', id, ok: false, error: String(e && e.message || e) }));
      }
    };
    ws.onclose = () => { ready = false; setTimeout(connect, 2000); };
    ws.onerror = () => {};
  }

  // 结果序列化：函数/大对象降级为可读字符串
  function safe(v) {
    try {
      if (v === undefined) return '(undefined)';
      if (typeof v === 'function') return '[Function ' + (v.name || '') + ']';
      if (typeof v === 'object' && !Array.isArray(v)) {
        // 常见：CryptoJS WordArray / Uint8Array / 对象 → 尽量给出 toString 或 hex
        if (typeof v.toString === 'function' && v.toString() !== '[object Object]') {
          const s = v.toString();
          if (typeof s === 'string' && s !== '[object Object]') return s;
        }
        if (v.words && v.sigBytes !== undefined && window.CryptoJS) {
          try { return window.CryptoJS.enc.Base64.stringify(v); } catch (e) {}
        }
      }
      if (v instanceof Uint8Array || v instanceof ArrayBuffer) {
        return Array.from(new Uint8Array(v)).map(b => b.toString(16).padStart(2, '0')).join('');
      }
      JSON.stringify(v);   // 可序列化就原样
      return v;
    } catch (e) {
      try { return String(v); } catch (e2) { return '(unserializable)'; }
    }
  }

  // 断线重连兜底：页面用定时器保活（部分 CSP 环境 setInterval 被限也尽力）
  setInterval(() => { if (!ready) { try { connect(); } catch (e) {} } }, 5000);
  connect();

  return '[jsrpc] client injected. __jsrpc ready. exposed=' + Object.keys(FN).length;
})();
