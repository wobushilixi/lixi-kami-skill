#!/usr/bin/env python3
"""web_kami_scan.py - Web 网页 / JS / HAR 的卡密与验证接口特征扫描（S1 分析用）。

用法:
    python web_kami_scan.py <目录|html|js|har> [--top N] [--json out.json]

覆盖目标:
    - 保存下来的网页目录（html / js / json / map）
    - 单个 .js / .html 文件
    - 浏览器导出的 .har 抓包文件（自动解析 URL、请求体、响应体）

输出分组命中：卡密词、验证语义、验证端点、Token/JWT、本地存储、加密、混淆、心跳计时。
只做本地只读分析，不发起任何网络请求。
"""

import argparse
import json
import os
import re
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

PATTERNS = {
    "cardkey": [
        r"card[-_ ]?key", r"cd[-_ ]?key", r"kami", r"ka[-_ ]?mi",
        r"cardno", r"card[-_]?code", r"activation[-_]?code",
        r"license[-_]?(key|code)", r"licence[-_]?key",
        r"serial[-_]?(number|no|key)", r"reg(ister)?[-_]?code",
        r"auth[-_]?code", r"redeem[-_]?code", r"卡密", r"激活码", r"注册码", r"授权码",
    ],
    "verify": [
        r"check[-_]?(license|auth|valid|activation|key|vip|member|card)",
        r"(license|auth|key|vip|member|card)[-_]?check",
        r"verif(y|ied|ication)", r"is[-_]?(valid|activated|licensed|vip|pro|member)",
        r"validate", r"authenticate", r"expire(d|_time|-time|s)?", r"expir(y|ation)",
        r"trial", r"remaining[-_]?(days|time|count)", r"days[-_]?left",
        r"unauthorized", r"not[-_]?activated", r"invalid[-_]?(key|code|license)",
        r"\bstatus\b\s*[:=]", r"\bcode\b\s*[:=]\s*0", r"\bsuccess\b\s*[:=]",
        r"授权", r"激活", r"未授权", r"已过期", r"到期", r"试用", r"验证失败",
    ],
    "endpoint": [
        r"https?://[A-Za-z0-9.\-]{3,}",
        r"(/api/|/v\d/)[A-Za-z0-9_\-/]{0,60}(auth|license|licence|active|activate"
        r"|verify|check|register|card|key|vip|member|user|login|pay|order)[A-Za-z0-9_\-/]{0,40}",
        r"fetch\s*\(", r"XMLHttpRequest", r"\$\.(get|post|ajax)",
        r"axios\.(get|post|request)", r"\.open\s*\(\s*['\"](GET|POST)",
        r"(url|api|endpoint)\s*[:=]\s*['\"][^'\"]{4,120}['\"]",
    ],
    "token": [
        r"\bJWT\b", r"eyJ[A-Za-z0-9_\-]{10,}", r"Authorization",
        r"Bearer\s+", r"\baccess[-_]?token\b", r"\brefresh[-_]?token\b",
        r"\btoken\b\s*[:=]", r"\bsession[-_]?id\b", r"\bsessionid\b",
        r"document\.cookie", r"\buid\b\s*[:=]", r"\bdevice[-_]?id\b",
    ],
    "storage": [
        r"localStorage", r"sessionStorage", r"indexedDB",
        r"\.(set|get)Item\s*\(", r"cookie",
        r"(expire|expiry|deadline|due)[-_]?(time|at|date)?",
        r"(vip|member|level|license|auth)[-_]?(state|status|flag|info|expire)",
    ],
    "crypto": [
        r"CryptoJS", r"\bAES\b", r"\bDES\b", r"\bRSA\b", r"\bMD5\b",
        r"\bSHA[-_]?(1|256|512)?\b", r"\bHMAC\b", r"btoa\s*\(", r"atob\s*\(",
        r"SubtleCrypto", r"crypto\.subtle", r"WebAssembly", r"\bwasm\b",
        r"\bsign\b\s*[:=]", r"md5\s*\(", r"hex_md5", r"sha1\s*\(", r"sha256\s*\(",
    ],
    "obfuscate": [
        r"\beval\s*\(", r"_0x[0-9a-fA-F]{4,}", r"String\.fromCharCode",
        r"\\x[0-9a-fA-F]{2}", r"Function\s*\(\s*['\"]", r"new\s+Function",
        r"\[[\"'][a-z][\"']\]\s*\[[\"']", r"jsfuck", r"obfuscator",
        r"\\u00[0-9a-fA-F]{2}", r"while\s*\(\s*!!\[\]\s*\)",
    ],
    "timing": [
        r"setInterval\s*\(", r"setTimeout\s*\(", r"Date\.now\s*\(",
        r"new\s+Date\s*\(", r"performance\.now", r"heartbeat",
        r"心跳", r"倒计时", r"countdown",
    ],
}

COMPILED = {g: [re.compile(p, re.IGNORECASE) for p in ps] for g, ps in PATTERNS.items()}

TEXT_EXT = {".js", ".html", ".htm", ".json", ".map", ".ts", ".vue", ".jsx", ".tsx", ".css"}


def scan_text(text, loc, hits, top_ctx=140):
    for lineno, line in enumerate(text.splitlines(), 1):
        if len(line) > 4000:
            line = line[:4000]
        for group, regs in COMPILED.items():
            for reg in regs:
                m = reg.search(line)
                if m:
                    hits[group].append({
                        "loc": loc, "pos": "L%d" % lineno,
                        "hit": m.group(0)[:60],
                        "ctx": line.strip()[:top_ctx],
                    })
                    break
            else:
                continue
            break


def scan_path(root, hits, args):
    count = 0
    if os.path.isfile(root):
        files = [root]
    else:
        files = []
        for dp, dns, fns in os.walk(root):
            dns[:] = [d for d in dns if not d.startswith((".git", "node_modules", ".cache"))]
            for fn in fns:
                if os.path.splitext(fn)[1].lower() in TEXT_EXT:
                    files.append(os.path.join(dp, fn))
    for fp in files:
        if count >= args.max_files:
            break
        try:
            if os.path.getsize(fp) > args.max_size * 1024 * 1024:
                continue
            with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                scan_text(f.read(), os.path.relpath(fp, root) if os.path.isdir(root)
                          else os.path.basename(fp), hits)
        except Exception as e:
            hits["_errors"].append({"loc": fp, "pos": "-", "hit": "read failed",
                                    "ctx": str(e)[:120]})
        count += 1
    return count


def scan_har(path, hits, args):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        try:
            data = json.load(f)
        except Exception as e:
            print("[-] HAR parse failed: %s" % e)
            return 0
    entries = data.get("log", {}).get("entries", [])
    n = 0
    for e in entries[: args.max_files]:
        req = e.get("request", {})
        res = e.get("response", {})
        url = req.get("url", "")
        blob_parts = [url]
        for part in (req.get("postData", {}).get("text", ""),
                     res.get("content", {}).get("text", "")):
            if part:
                blob_parts.append(part)
        # URL 与状态码单独报告
        if any(k in url.lower() for k in ("auth", "license", "verify", "check",
                                          "card", "key", "vip", "member",
                                          "activate", "register", "login", "pay")):
            hits["endpoint"].append({
                "loc": "HAR", "pos": str(res.get("status", "?")),
                "hit": url[:110], "ctx": (req.get("method", "") + " " + url)[:140],
            })
        scan_text("\n".join(blob_parts), "HAR:%s" % url[:70], hits)
        n += 1
    return n


def main():
    ap = argparse.ArgumentParser(description="Web 卡密 / 验证接口特征扫描")
    ap.add_argument("target", help="网页目录 / html / js / .har")
    ap.add_argument("--top", type=int, default=10, help="每组显示条数")
    ap.add_argument("--json", dest="json_out")
    ap.add_argument("--max-files", type=int, default=400)
    ap.add_argument("--max-size", type=int, default=30, help="单文件上限 MB")
    args = ap.parse_args()

    t = args.target
    if not os.path.exists(t):
        print("[-] not found: %s" % t)
        return 2

    hits = {g: [] for g in PATTERNS}
    hits["_errors"] = []

    print("[+] target: %s" % t)
    if t.lower().endswith(".har"):
        n = scan_har(t, hits, args)
        print("[+] type  : HAR (%d entries)" % n)
    else:
        n = scan_path(t, hits, args)
        print("[+] type  : %s (%d files)" % ("dir" if os.path.isdir(t) else "file", n))

    total = sum(len(v) for k, v in hits.items() if not k.startswith("_"))
    print("[+] total hits: %d\n" % total)

    out = {}
    for group in PATTERNS:
        items = hits[group]
        out[group] = items
        if not items:
            continue
        print("== %-10s (%d hits)" % (group, len(items)))
        for it in items[: args.top]:
            print("   %-40s %-8s | %s" % (it["loc"][:40], it["pos"], it["hit"][:55]))
        if len(items) > args.top:
            print("   ... %d more" % (len(items) - args.top))
        print()

    if hits["_errors"]:
        print("== errors (%d)" % len(hits["_errors"]))
        for it in hits["_errors"][:5]:
            print("   %s: %s" % (it["loc"], it["ctx"]))

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump({"target": t, "hits": out, "errors": hits["_errors"]},
                      f, ensure_ascii=False, indent=2)
        print("[+] json written: %s" % args.json_out)

    if total == 0:
        print("[-] 无命中：可能逻辑在 WASM / 远程加载的 JS / 纯服务端。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
