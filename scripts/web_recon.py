#!/usr/bin/env python3
"""web_recon.py - Web 逆向一键侦察（HAR / 目录 / URL 三模式）——对标二进制的 s1_recon.py

解决什么问题：
    Web 逆向成功率低，根因是「只有关键词扫描，没有侦察深度」——不知道哪个 JS 是主逻辑、
    哪些参数是签名、接口链是什么、有没有反调试、下一步该走哪条路。本脚本把这些一次算清。

用法:
    python web_recon.py capture.har                  # 模式1：HAR 抓包（最可靠，用户总能导出）
    python web_recon.py ./saved_site                 # 模式2：另存的网页目录 / JS 包目录
    python web_recon.py --url https://example.com    # 模式3：在线抓 HTML+JS（可能被风控，失败会说明）
    # 通用：--out work/web_x   --top 30

产出（默认 work/web_<名>/）:
    web_recon.md     报告：接口清单 + 参数分类 + JS 排名 + 混淆/反调试 + 下一步路由
    web_recon.json   结构化结果

分析能力:
    HAR : 接口清单与分类 / 参数分类（sign 类·密文类·固定值） / 响应结构 / JWT / 请求链 / 轮询
    JS  : 混淆类型（obfuscator.io·webpack·JSVMP） / 加密库（CryptoJS/SM/AES/RSA） /
          反调试迹象（debugger/测时/toString 校验） / Worker/WASM / 接口字符串 / 签名函数候选
    HTML: 框架识别 / 内联脚本 / 表单与接口引用
"""

import argparse
import base64
import json
import os
import re
import sys
import urllib.parse
import urllib.request
from collections import defaultdict

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# ---------------- 特征库 ----------------
STATIC_EXT = re.compile(r"\.(js|css|png|jpe?g|gif|svg|woff2?|ttf|ico|mp4|webp|map)(\?|$)", re.I)
SIGN_PARAM = re.compile(
    r"^(sign|signature|_sign|sig|nonce|_nonce|timestamp|_t|ts|time|_time|rand|random|"
    r"salt|token|access_token|app_?key|secret|client_?id|device_?id|uuid|dfp|hd|w_rid|"
    r"a_?bogus|x-?bogus|x-?gnarly|ms_?token|session|csrf)\b", re.I)
ENC_LIKE = re.compile(r"^[A-Za-z0-9+/=_\-]{32,}$")
JWT_RE = re.compile(r"^eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*$")
VERIFY_HINT = re.compile(
    r"(verify|valida|check|login|auth|activat|activate|card|kami|redeem|licen[sc]e|"
    r"order|pay|user|member|vip|dialog|challenge|risk|device|token)", re.I)

OBF_PATTERNS = [
    ("obfuscator.io", re.compile(r"_0x[0-9a-fA-F]{4,}")),
    ("webpack", re.compile(r"__webpack_require__|webpackChunk|webpackJsonp")),
    ("JSVMP/VM", re.compile(r"while\s*\(\s*(?:1|true)\s*\)\s*\{\s*switch|opcode|bytecode", re.I)),
    ("自执行字符串数组", re.compile(r"\(\s*function\s*\([^)]*\)\s*\{\s*var\s+_0x")),
    ("动态执行", re.compile(r"eval\s*\(|new\s+Function\s*\(")),
]
CRYPTO_LIBS = [
    ("CryptoJS", re.compile(r"CryptoJS|Crypto\.JS")),
    ("AES/DES", re.compile(r"\bAES\b|\bDES\b|createCipher|aesEncrypt|aesDecrypt", re.I)),
    ("RSA", re.compile(r"JSEncrypt|setPublicKey|RSAKey|pkcs1|rsaEncrypt", re.I)),
    ("国密 SM2/SM3/SM4", re.compile(r"sm2|sm3|sm4|sm2Encrypt|sm4Encrypt", re.I)),
    ("MD5/SHA", re.compile(r"md5|sha1|sha256|hex_md5|Sha256", re.I)),
    ("Base64 变种", re.compile(r"atob\(|btoa\(|Base64|base64Encode|_b64")),
    ("XXTEA/自定义", re.compile(r"xxtea|xtea|teaEncrypt", re.I)),
]
ANTIDBG = [
    ("debugger 断点陷阱", re.compile(r"\bdebugger\b")),
    ("DevTools 检测", re.compile(r"devtools|debugger_?check|isDevTool|debugDetector", re.I)),
    ("控制台检测", re.compile(r"console\.(log|clear)\s*=|firebug|__console|console\.firebug", re.I)),
    ("执行时间差检测", re.compile(r"performance\.now|Date\.now\(\)\s*-\s*start", re.I)),
    ("函数 toString 校验", re.compile(r"toString\(\)\.(indexOf|includes|search)|native code", re.I)),
    ("环境指纹检测", re.compile(r"navigator\.webdriver|userAgent.*Headless|phantom|selenium|cdn_?headless", re.I)),
]
RUNTIME = [
    ("Worker", re.compile(r"new\s+Worker\s*\(")),
    ("WASM", re.compile(r"\.wasm|WebAssembly\.(instantiate|compile)")),
    ("WebSocket", re.compile(r"new\s+WebSocket\s*\(")),
]
EP_RE = re.compile(r"""["'`]((?:https?://[\w.\-]+)?/[A-Za-z0-9_\-./{}$:]{3,80})["'`]""")
SIGN_FN_RE = re.compile(
    r"(?:function\s+|const\s+|var\s+|let\s+|\.)([A-Za-z_$][\w$]*?(?:sign|encrypt|generate|make|build|calc|get|create)[A-Za-z_$]*)\s*[=:(]",
    re.I)


def kind_of(path, mime=""):
    if STATIC_EXT.search(path):
        return "STATIC"
    if VERIFY_HINT.search(path):
        return "VERIFY-LIKE"
    if "/api" in path or "json" in (mime or ""):
        return "API"
    return "OTHER"


def classify_params(params):
    """参数分类：sign 类 / 密文类 / 固定值（跨条目比对由调用方做）"""
    out = []
    for k, v in params.items():
        v = "" if v is None else str(v)
        tags = []
        if SIGN_PARAM.search(k):
            tags.append("sign类")
        if JWT_RE.match(v):
            tags.append("JWT")
        elif ENC_LIKE.match(v) and len(v) >= 32 and not re.match(r"^[0-9]+$", v):
            tags.append("密文类(可能加密/编码)")
        if re.match(r"^1[0-9]{12}$", v):
            tags.append("时间戳ms")
        elif re.match(r"^1[0-9]{9}$", v):
            tags.append("时间戳s")
        out.append({"name": k, "len": len(v), "preview": v[:40], "tags": tags})
    return out


# ---------------- HAR ----------------
def analyze_har(path, top):
    data = json.load(open(path, encoding="utf-8", errors="ignore"))
    entries = data.get("log", {}).get("entries", [])
    eps = defaultdict(lambda: {"count": 0, "kind": None, "params": [], "resp_keys": set(),
                               "cookie_set": False, "samples": []})
    flow = []
    for e in entries:
        req = e.get("request", {})
        res = e.get("response", {})
        url = req.get("url", "")
        u = urllib.parse.urlsplit(url)
        p = u.path or "/"
        mime = (res.get("content", {}) or {}).get("mimeType", "")
        k = kind_of(p, mime)
        key = "%s %s%s" % (req.get("method", "?"), u.netloc, p)
        d = eps[key]
        d["count"] += 1
        d["kind"] = d["kind"] or k
        # 参数
        params = {}
        for q in (u.query or "").split("&"):
            if "=" in q:
                a, b = q.split("=", 1)
                params[urllib.parse.unquote_plus(a)] = urllib.parse.unquote_plus(b)
        pd = req.get("postData", {}) or {}
        if pd.get("text"):
            txt = pd["text"]
            try:
                j = json.loads(txt)
                if isinstance(j, dict):
                    params.update({kk: vv for kk, vv in j.items()
                                   if isinstance(vv, (str, int, float))})
            except Exception:
                for q in txt.split("&"):
                    if "=" in q:
                        a, b = q.split("=", 1)
                        params[urllib.parse.unquote_plus(a)] = urllib.parse.unquote_plus(b)
        if len(d["samples"]) < 3:
            d["samples"].append(params)
        # 响应 JSON 键 / set-cookie
        txt = (res.get("content", {}) or {}).get("text", "")
        if txt:
            try:
                rj = json.loads(txt)
                if isinstance(rj, dict):
                    d["resp_keys"].update(list(rj.keys())[:15])
            except Exception:
                pass
        for h in res.get("headers", []) or []:
            if h.get("name", "").lower() == "set-cookie":
                d["cookie_set"] = True
        flow.append({"t": e.get("startedDateTime", ""), "m": req.get("method", "?"),
                     "url": url[:110], "status": res.get("status", "?"), "kind": k})

    # 参数分类（用样本比对固定值）
    api_rows = []
    for key, d in sorted(eps.items(), key=lambda x: -x[1]["count"]):
        if d["kind"] == "STATIC":
            continue
        samples = d["samples"]
        agg = {}
        for s in samples:
            for k2, v2 in s.items():
                agg.setdefault(k2, []).append(str(v2))
        fixed = [k2 for k2, vs in agg.items() if len(vs) > 1 and len(set(vs)) == 1]
        base = classify_params({k2: vs[0] for k2, vs in agg.items()})
        for r in base:
            if r["name"] in fixed:
                r["tags"].append("跨请求固定")
        api_rows.append({"endpoint": key, "kind": d["kind"], "count": d["count"],
                         "params": base, "resp_keys": sorted(d["resp_keys"]),
                         "set_cookie": d["cookie_set"]})
    return {"mode": "HAR", "entries": len(entries), "endpoints": len(eps),
            "api_rows": api_rows[:top * 2], "flow": flow[:80]}


# ---------------- JS / 目录 ----------------
def analyze_js_text(txt, name, top):
    res = {"file": name, "size": len(txt), "obf": [], "crypto": [], "antidbg": [],
           "runtime": [], "endpoints": [], "sign_fns": []}
    for label, rx in OBF_PATTERNS:
        n = len(rx.findall(txt))
        if n > 0:
            res["obf"].append((label, n))
    for label, rx in CRYPTO_LIBS:
        n = len(rx.findall(txt))
        if n > 0:
            res["crypto"].append((label, n))
    for label, rx in ANTIDBG:
        n = len(rx.findall(txt))
        if n > 0:
            res["antidbg"].append((label, n))
    for label, rx in RUNTIME:
        n = len(rx.findall(txt))
        if n > 0:
            res["runtime"].append((label, n))
    eps = set()
    for m in EP_RE.finditer(txt):
        s = m.group(1)
        if len(s) > 3:
            eps.add(s)
    res["endpoints"] = sorted(eps)[:top]
    fns = set()
    for m in SIGN_FN_RE.finditer(txt):
        fns.add(m.group(1))
    res["sign_fns"] = sorted(fns)[:20]
    # 评分：语义密度
    score = (len(res["crypto"]) * 3 + len(res["obf"]) * 2 +
             min(len(res["sign_fns"]), 10) + min(len(res["endpoints"]), 20) // 2)
    res["score"] = score
    return res


def analyze_dir(root, top):
    files = []
    har_files = []
    for dp, dns, fns in os.walk(root):
        for fn in fns:
            fp = os.path.join(dp, fn)
            if fn.lower().endswith(".har"):
                har_files.append(fp)
            elif fn.lower().endswith((".js", ".mjs", ".html", ".htm", ".json")):
                files.append(fp)
    js_rows = []
    html_rows = []
    for fp in files:
        try:
            if os.path.getsize(fp) > 12 * 1024 * 1024:
                continue
            txt = open(fp, encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        rel = os.path.relpath(fp, root)
        if fp.lower().endswith((".js", ".mjs")):
            js_rows.append(analyze_js_text(txt, rel, top))
        elif fp.lower().endswith((".html", ".htm")):
            fw = []
            for label, rx in (("Vue", r"vue(\.min)?\.js|__VUE__"),
                              ("React", r"react|__REACT"),
                              ("Next.js", r"__NEXT_DATA__"),
                              ("Nuxt", r"__NUXT__"),
                              ("jQuery", r"jquery"),
                              ("Svelte", r"svelte"),
                              ("uni-app", r"uni-app|__uniConfig")):
                if re.search(rx, txt, re.I):
                    fw.append(label)
            inline = len(re.findall(r"<script(?![^>]*src)", txt, re.I))
            scripts = re.findall(r"""<script[^>]*src=["']([^"']+)["']""", txt, re.I)
            forms = re.findall(r"""<form[^>]*action=["']([^"']*)["']""", txt, re.I)
            html_rows.append({"file": rel, "frameworks": fw, "inline_scripts": inline,
                              "external_scripts": scripts[:20], "forms": forms[:10]})
    js_rows.sort(key=lambda r: -r["score"])
    # 目录里的 har 抓包（独立收集，见 har_files）
    return {"mode": "DIR", "js": js_rows[:top], "html": html_rows[:10],
            "hars_found": [os.path.relpath(h, root) for h in har_files[:5]],
            "total_js": len(js_rows)}


# ---------------- URL ----------------
def fetch(url, timeout=20, limit=2 * 1024 * 1024):
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/126 Safari/537.36"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read(limit)
        return r.geturl(), data.decode("utf-8", "ignore")


def analyze_url(url, top):
    out = {"mode": "URL", "url": url}
    try:
        final, html = fetch(url)
        out["final_url"] = final
        out["html_len"] = len(html)
        fw = []
        for label, rx in (("Vue", r"vue(\.min)?\.js|__VUE__"), ("React", r"react|__REACT"),
                          ("Next.js", r"__NEXT_DATA__"), ("Nuxt", r"__NUXT__"),
                          ("jQuery", r"jquery"), ("uni-app", r"uni-app|__uniConfig"),
                          ("ThinkPHP/后端模板", r"think|laravel|csrf[_-]?token"),):
            if re.search(rx, html, re.I):
                fw.append(label)
        out["frameworks"] = fw
        scripts = re.findall(r"""<script[^>]*src=["']([^"']+)["']""", html, re.I)
        base = urllib.parse.urlsplit(final)
        js_rows = []
        fetched = 0
        for s in scripts[:25]:
            if s.startswith("//"):
                s = base.scheme + ":" + s
            elif s.startswith("/"):
                s = "%s://%s%s" % (base.scheme, base.netloc, s)
            elif not s.startswith("http"):
                continue
            try:
                _, jtxt = fetch(s, timeout=15)
                js_rows.append(analyze_js_text(jtxt, s, top))
                fetched += 1
            except Exception:
                continue
        js_rows.sort(key=lambda r: -r["score"])
        out["js"] = js_rows[:top]
        out["js_fetched"] = fetched
        out["scripts_total"] = len(scripts)
    except Exception as e:
        out["error"] = ("抓取失败: %s —— 可能被风控/需要 JS 渲染。"
                        "改用浏览器打开后导出 HAR（模式1），或用 chrome-devtools-mcp / stealth-browser-mcp 走 live 路线。" % e)
    return out


# ---------------- 报告 ----------------
def route_advice(res, cand_eps):
    lines = []
    sign_hits = [p for row in cand_eps for p in row["params"] if "sign类" in p["tags"]]
    enc_hits = [p for row in cand_eps for p in row["params"] if "密文类(可能加密/编码)" in p["tags"]]
    if sign_hits:
        lines.append("**存在签名类参数**（%s）→ 走签名链逆向：`js-reverse-mcp` 的 "
                     "`get_request_initiator`/`set_breakpoint_on_text` 断点，或按 HAR 里的 JS 文件排名"
                     "用 `references/js-signature-reverse.md` 五阶段流程。" % ", ".join(sorted({p['name'] for p in sign_hits})[:6]))
    if enc_hits:
        lines.append("**存在密文类参数**（%s）→ 先找加密函数：按 JS 排名的 Crypto 命中去下断点，"
                     "或用 `references/crypto-signature-playbook.md` 的加密原语速查表对号。" % ", ".join(sorted({p['name'] for p in enc_hits})[:6]))
    if not sign_hits and not enc_hits:
        lines.append("未见明显签名/密文参数 → 大概率 B/C 类（服务端判定）：优先改客户端**解析后的判定分支**"
                     "（`references/web-card-key.md` §四），别浪费时间伪造响应。")
    lines.append("**live 路线**（需要动态观察时）：`chrome-devtools-mcp`（常规）或 `stealth-browser-mcp`（被风控时）；"
                 "**静态路线**（推荐先做）：HAR + JS 文件离线分析，Node 复现，不依赖浏览器在线。")
    lines.append("**补环境失败**（Node 跑不动时）：`tools/reverse-cases/tiktok-x-bogus/node_harness.js` 模板 + "
                 "`references/js-case-studies.md`。")
    return lines


def main():
    ap = argparse.ArgumentParser(description="Web 逆向一键侦察（HAR/目录/URL）")
    ap.add_argument("target", nargs="?", help="HAR 文件 或 目录")
    ap.add_argument("--url", help="在线抓取模式")
    ap.add_argument("--out", help="输出目录（默认 work/web_<名>）")
    ap.add_argument("--top", type=int, default=25)
    args = ap.parse_args()

    if not args.target and not args.url:
        print(__doc__)
        return 2
    name = "url" if args.url else os.path.splitext(os.path.basename(os.path.normpath(args.target)))[0]
    out = args.out or os.path.join("work", "web_" + name)
    os.makedirs(out, exist_ok=True)

    if args.url:
        res = analyze_url(args.url, args.top)
    elif args.target.lower().endswith(".har"):
        try:
            res = analyze_har(args.target, args.top)
        except Exception as e:
            print("[-] HAR 解析失败：%s" % e)
            print("    确认它是浏览器 Network 面板导出的 .har（JSON 格式）")
            return 2
    elif os.path.isdir(args.target):
        res = analyze_dir(args.target, args.top)
    else:
        print("[-] 目标不支持（需要 .har / 目录 / --url）")
        return 2

    # ---- 报告 ----
    L = ["# Web 侦察报告", "",
         "> 由 `scripts/web_recon.py` 自动生成。结构比关键词扫描深一层：接口/参数/JS/路由。", ""]
    if res.get("mode") == "HAR":
        L += ["## 1. 抓包概览", "- 请求总数：%d｜独立接口：%d" % (res["entries"], res["endpoints"]), ""]
        L += ["## 2. 接口清单与参数分类", "", "| 接口 | 类型 | 次数 | 参数（标记） | 响应键 |", "|---|---|---|---|---|"]
        for r in res["api_rows"]:
            pstr = ", ".join("%s%s" % (p["name"], ("[%s]" % "/".join(p["tags"])) if p["tags"] else "")
                             for p in r["params"][:8])
            L.append("| `%s` | %s | %d | %s | %s |" % (r["endpoint"][:60], r["kind"], r["count"],
                                                      pstr[:110], ",".join(r["resp_keys"][:6])))
        L += ["", "## 3. 请求链（前 30 条）", "```"]
        for f in res["flow"][:30]:
            L.append("%-6s %-3s %s -> %s" % (f["t"][11:19], f["status"], f["m"], f["url"][:90]))
        L += ["```", ""]
        L += ["## 4. 下一步路由"] + ["- " + x for x in route_advice(res, res["api_rows"])]
    elif res.get("mode") == "DIR":
        L += ["## 1. JS 文件排名（先看前几个）", "",
              "| 文件 | 大小 | 评分 | 混淆 | 加密库 | 反调试 | 运行时 |", "|---|---|---|---|---|---|---|"]
        for r in res["js"]:
            L.append("| `%s` | %dKB | %d | %s | %s | %s | %s |" % (
                r["file"][:60], r["size"] // 1024, r["score"],
                ",".join("%s×%d" % o for o in r["obf"][:3]) or "-",
                ",".join("%s×%d" % o for o in r["crypto"][:3]) or "-",
                ",".join("%s×%d" % o for o in r["antidbg"][:3]) or "-",
                ",".join("%s×%d" % o for o in r["runtime"][:2]) or "-"))
        L += ["", "## 2. 高评分 JS 的关键情报"]
        for r in res["js"][:5]:
            L.append("### `%s`（%dKB，评分 %d）" % (r["file"], r["size"] // 1024, r["score"]))
            if r["sign_fns"]:
                L.append("- 签名/加密函数候选：%s" % ", ".join("`%s`" % f for f in r["sign_fns"][:10]))
            if r["endpoints"]:
                L.append("- 接口字符串：%s" % ", ".join("`%s`" % e for e in r["endpoints"][:10]))
            L.append("")
        if res["html"]:
            L += ["## 3. HTML 概况", "| 文件 | 框架 | 内联脚本 | 表单 |", "|---|---|---|---|"]
            for h in res["html"]:
                L.append("| `%s` | %s | %d | %s |" % (h["file"][:50], ",".join(h["frameworks"]) or "-",
                                                     h["inline_scripts"], ",".join(h["forms"][:3]) or "-"))
            L.append("")
        if res["hars_found"]:
            L += ["## 4. 发现 HAR 抓包：%s → 用模式1 再跑一次（深度分析参数与链路）" %
                  ", ".join(os.path.basename(h) for h in res["hars_found"]), ""]
        L += ["## 5. 下一步路由"]
        L += ["- 有 HAR 就先跑 HAR 模式（参数分类+链路）；没有 → 让用户导出 HAR（浏览器 Network → 导出）"]
        L += ["- " + x for x in route_advice(res, [{"params": []}])]
    else:
        L += ["## 1. 在线抓取", "- 结果：%s" % ("OK" if not res.get("error") else res["error"]), ""]
        if not res.get("error"):
            L += ["- 框架：%s｜脚本 %d 个（成功拉取 %d）" % (",".join(res.get("frameworks", [])) or "-",
                                                          res.get("scripts_total", 0), res.get("js_fetched", 0)), ""]
            L += ["## 2. JS 文件排名", "", "| 文件 | 大小 | 评分 | 混淆 | 加密库 | 反调试 |", "|---|---|---|---|---|---|"]
            for r in res.get("js", []):
                L.append("| `%s` | %dKB | %d | %s | %s | %s |" % (
                    r["file"][-60:], r["size"] // 1024, r["score"],
                    ",".join("%s×%d" % o for o in r["obf"][:3]) or "-",
                    ",".join("%s×%d" % o for o in r["crypto"][:3]) or "-",
                    ",".join("%s×%d" % o for o in r["antidbg"][:3]) or "-"))
            L += ["", "## 3. 下一步路由"] + ["- " + x for x in route_advice(res, [{"params": []}])]

    md = os.path.join(out, "web_recon.md")
    open(md, "w", encoding="utf-8").write("\n".join(L))
    json.dump(res, open(os.path.join(out, "web_recon.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=2, default=str)
    print("[+] 报告 → %s" % md)
    if res.get("mode") == "HAR":
        print("    接口 %d（VERIFY-LIKE %d）" % (
            res["endpoints"],
            sum(1 for r in res["api_rows"] if r["kind"] == "VERIFY-LIKE")))
    elif res.get("mode") == "DIR":
        print("    JS %d 个，前 3 名：%s" % (res["total_js"],
              ", ".join("%s(%d分)" % (r["file"][-40:], r["score"]) for r in res["js"][:3])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
