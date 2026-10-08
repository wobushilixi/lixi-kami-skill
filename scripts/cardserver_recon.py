#!/usr/bin/env python3
"""cardserver_recon.py - 卡密/网络验证系统【服务端】侦察（后台凭证获取第一步）

场景：目标是一个网络验证卡密系统的服务端（自建或开源），目标是拿到后台账号密码。
      本脚本做「拿凭证之前必须做的信息收集」——被动为主 + 轻量主动探测（限速限总量）。

用法:
    python cardserver_recon.py https://kami.example.com            # 服务端侦察
    python cardserver_recon.py --from-client target.apk            # 先从客户端抽服务端线索
    python cardserver_recon.py https://x.com --from-client app.exe # 两条一起跑（推荐）
    python cardserver_recon.py https://x.com --rate 1.0 --max-req 40 --out work/cs_x

做什么（全部只读 GET/HEAD，不改任何数据）:
    1) 指纹   : Server/X-Powered-By 头、首页 title、技术栈（PHP/Java/ThinkPHP/Laravel/Node/ASP.NET）、
                已知卡密系统特征（天御/易游/飘零/飞扬/至简/索玛/独角数卡/发卡 等）
    2) 后台面 : 探测常见后台路径（/admin /admin.php /manage /houtai /backend ...），记录状态码
    3) 泄漏面 : 探测常见泄漏文件（/.git/config /.env /www.zip /db.sql /config.php.bak /phpinfo.php ...）
    4) API 线索: 首页/JS 里抽取接口路径（/api/verify /api/card ...）
    5) 路由   : 输出「下一步攻击面优先级」（按代价从低到高：泄漏→已知漏洞→认证攻击→注入→爆破）

安全与纪律:
    - 默认限速 0.4s/请求、总上限 80 请求；只读、无 payload、不改数据
    - 在线爆破是**最后手段**且默认不做（本脚本不爆破）；要爆破须用户明确要求并设边界
    - 所有发现写 work/ 目录落档（E# 台账配套），报告写清证据（状态码/响应特征）
"""

import argparse
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126 Safari/537.36")

# 后台路径候选（低成本探测，仅状态码判定）
ADMIN_PATHS = [
    "/admin", "/admin/", "/admin.php", "/admin/login", "/admin/index.php",
    "/manage", "/manage/", "/manager", "/houtai", "/ht", "/backend", "/backend/",
    "/console", "/dashboard", "/login", "/login.php", "/admin/login.php",
    "/system", "/sys", "/api/admin", "/api/admin/", "/admin/index.html",
    "/wp-admin/", "/administrator/", "/user/admin", "/seller", "/merchant",
    "/admin_login.php", "/adm", "/a/", "/admin_home.php", "/daili", "/agent",
]

# 泄漏文件候选（只读取回看特征）
LEAK_FILES = [
    "/.git/config", "/.git/HEAD", "/.env", "/.env.bak", "/www.zip", "/web.zip",
    "/backup.zip", "/backup.tar.gz", "/wwwroot.zip", "/db.sql", "/database.sql",
    "/config.php.bak", "/config.php~", "/config.bak", "/.svn/entries",
    "/phpinfo.php", "/info.php", "/test.php", "/test.html", "/composer.json",
    "/package.json", "/readme.txt", "/README.md", "/install/", "/install.php",
    "/adminer.php", "/phpmyadmin/", "/pma/", "/dbadmin/",
]

# 已知卡密/发卡系统特征（响应体/标题）
PLATFORM_SIGS = [
    ("易游网络验证", r"易游|yy?kami|yiyou"),
    ("天御网络验证", r"天御|tyun|52tyun"),
    ("飘零网络验证", r"飘零|piaoling"),
    ("飞扬网络验证", r"飞扬|feiyang"),
    ("至简网络验证", r"至简|zhijian"),
    ("索玛 SOMA", r"soma|索玛"),
    ("独角数卡", r"dujiaoka|独角数卡"),
    ("彩虹/易支付系发卡", r"epay|易支付|发卡网"),
    ("卡密宝", r"卡密宝|kamibao"),
    ("酷爱/华夏验证", r"酷爱|华夏验证|huaxia"),
    ("自研/魔改", r"网络验证|卡密系统|授权系统|card.?key|kami"),
]

STACK_SIGS = [
    ("PHP", r"X-Powered-By:\s*PHP|\.php|thinkphp|laravel|phpmyadmin"),
    ("ThinkPHP", r"ThinkPHP|think_var|tp5|topthink"),
    ("Laravel", r"laravel_session|XSRF-TOKEN|laravel"),
    ("Java/Spring", r"JSESSIONID|java\.lang|Whitelabel Error|org\.springframework|SpringBoot"),
    ("Node.js", r"X-Powered-By:\s*Express|koa|nestjs|NestFactory|X-Powered-By:\s*Node"),
    ("ASP.NET", r"ASP\.NET|__VIEWSTATE|aspnet_sessionId"),
    ("Go", r"X-Powered-By:\s*Go|go-http-client|Gin-gonic|gin\.Default|GinEngine"),
    ("Nginx", r"nginx"),
    ("Apache", r"Apache"),
    ("宝塔面板", r"btwaf|宝塔|BT-Panel"),
]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, reqo, fp, code, msg, headers, newurl):
        return None    # 不跟随：让 301/302 以 HTTPError 形式返回（保留 Location）


_OPENER = urllib.request.build_opener(_NoRedirect)


def req(url, method="GET", timeout=12, max_bytes=64 * 1024, rate=0.4, allow_redirects=False):
    """只读请求：GET/HEAD，限大小；返回 (status, headers, body[:max_bytes], final_url, err)。"""
    time.sleep(rate)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    r = urllib.request.Request(url, method=method, headers={
        "User-Agent": UA, "Accept": "*/*", "Accept-Language": "zh-CN,zh;q=0.9"})
    try:
        with _OPENER.open(r, timeout=timeout) as resp:
            body = b""
            if method == "GET":
                body = resp.read(max_bytes)
            hdrs = dict(resp.headers)
            return resp.status, hdrs, body, resp.geturl(), None
    except urllib.error.HTTPError as e:
        try:
            body = e.read(max_bytes) if method == "GET" else b""
        except Exception:
            body = b""
        return e.code, dict(e.headers or {}), body, url, None
    except Exception as e:
        return None, {}, b"", url, str(e)


def from_client(path, out_dir):
    """从客户端（APK/EXE/ELF/目录）里抽服务端线索：URL/域名/路径/疑似密钥。"""
    print("[*] 从客户端提取服务端线索: %s" % path)
    blobs = []
    if os.path.isdir(path):
        for dp, dns, fns in os.walk(path):
            for fn in fns:
                fp = os.path.join(dp, fn)
                try:
                    if os.path.getsize(fp) > 60 * 1024 * 1024:
                        continue
                    with open(fp, "rb") as f:
                        blobs.append((fn, f.read()))
                except Exception:
                    continue
    elif zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            for i in z.infolist():
                if i.file_size > 80 * 1024 * 1024:
                    continue
                if i.filename.endswith((".dex", ".so", ".xml", ".json", ".js", ".txt", "") or
                                       i.filename.startswith(("assets/", "lib/"))):
                    try:
                        blobs.append((i.filename, z.read(i)))
                    except Exception:
                        continue
    else:
        blobs.append((os.path.basename(path), open(path, "rb").read()))

    url_re = re.compile(rb"https?://[\w.\-:/%?=&@#]{4,120}")
    ip_re = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b")
    path_re = re.compile(rb"/api/[\w/]{2,60}|/(?:admin|manage|houtai|verify|card|kami)[\w/]{0,40}")
    key_re = re.compile(rb"(?:secret|appkey|app_key|api_?key|token)['\"]?\s*[:=]\s*['\"]([\w\-]{8,64})['\"]", re.I)

    urls, ips, paths, keys = set(), set(), set(), set()
    for name, d in blobs:
        for m in url_re.findall(d):
            try:
                urls.add(m.decode("utf-8", "replace"))
            except Exception:
                pass
        for m in ip_re.findall(d):
            ips.add(m.decode())
        for m in path_re.findall(d):
            paths.add(m.decode("utf-8", "replace"))
        for m in key_re.findall(d):
            keys.add(m.decode("utf-8", "replace"))
    res = {"client": os.path.abspath(path), "urls": sorted(urls)[:60], "ips": sorted(ips)[:40],
           "paths": sorted(paths)[:40], "keys_like": sorted(keys)[:20]}
    print("    URL %d / IP %d / 路径 %d / 疑似密钥 %d" % (
        len(res["urls"]), len(res["ips"]), len(res["paths"]), len(res["keys_like"])))
    json.dump(res, open(os.path.join(out_dir, "client_extract.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=2)
    return res


def main():
    ap = argparse.ArgumentParser(description="卡密系统服务端侦察（只读，限速）")
    ap.add_argument("url", nargs="?", help="服务端地址（http(s)://host[:port]）")
    ap.add_argument("--from-client", help="先从客户端（APK/EXE/ELF/目录）抽服务端线索")
    ap.add_argument("--rate", type=float, default=0.4, help="请求间隔秒（默认 0.4）")
    ap.add_argument("--max-req", type=int, default=80, help="总请求上限（默认 80）")
    ap.add_argument("--out", help="输出目录（默认 work/cardsrv_<host>）")
    ap.add_argument("--no-leak", action="store_true", help="跳过泄漏文件探测")
    ap.add_argument("--no-admin", action="store_true", help="跳过后台路径探测")
    args = ap.parse_args()

    if not args.url and not args.from_client:
        print(__doc__)
        return 2

    name = "client"
    if args.url:
        u = urllib.parse.urlsplit(args.url if "://" in args.url else "http://" + args.url)
        name = u.netloc.replace(":", "_").replace(".", "_")
    out = args.out or os.path.join("work", "cardsrv_" + name)
    os.makedirs(out, exist_ok=True)
    report = {"target": args.url, "findings": {}, "requests": 0, "budget": args.max_req}

    def budget_ok():
        return report["requests"] < args.max_req

    def do(url, method="GET"):
        if not budget_ok():
            return None, {}, b"", url, "预算耗尽"
        report["requests"] += 1
        return req(url, method=method, rate=args.rate)

    L = ["# 卡密系统服务端侦察报告", "",
         "> 由 `scripts/cardserver_recon.py` 生成（只读、限速 %ss、上限 %d 请求）。**所有结论需人工复核。**"
         % (args.rate, args.max_req), ""]

    # 0) 客户端线索
    if args.from_client:
        ce = from_client(args.from_client, out)
        report["findings"]["client_extract"] = ce
        L += ["## 0. 客户端提取的服务端线索", "",
              "- URL：%s" % (", ".join(ce["urls"][:10]) or "无"),
              "- IP：%s" % (", ".join(ce["ips"][:10]) or "无"),
              "- 路径：%s" % (", ".join(ce["paths"][:10]) or "无"),
              "- 疑似密钥：%s" % (", ".join(ce["keys_like"][:6]) or "无"), ""]
        if not args.url and ce["urls"]:
            args.url = ce["urls"][0]
            print("[*] 未给 URL，使用客户端第一个 URL 继续: %s" % args.url)

    if not args.url:
        print("[-] 没有可侦察的 URL（客户端线索里也没有）")
        open(os.path.join(out, "cardserver_recon.md"), "w", encoding="utf-8").write("\n".join(L))
        return 1

    base = args.url.rstrip("/")
    if "://" not in base:
        base = "http://" + base

    # 1) 首页指纹
    st, hdrs, body, final, err = do(base)
    print("[1] 首页: %s %s" % (st, err or ""))
    fp = {"status": st, "error": err, "server": hdrs.get("Server", ""),
          "powered": hdrs.get("X-Powered-By", ""), "final_url": final}
    text = body.decode("utf-8", "replace")
    m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    fp["title"] = (m.group(1).strip()[:100] if m else "")
    fp["stack"] = [n for n, rx in STACK_SIGS if re.search(rx, text, re.I) or re.search(rx, fp["server"] + fp["powered"], re.I)]
    fp["platform"] = [n for n, rx in PLATFORM_SIGS if re.search(rx, text, re.I)
                      or re.search(rx, fp["title"], re.I)]
    fp["api_like"] = sorted(set(re.findall(r"""["'`](/api/[\w/.\-]{2,80})["'`]""", text)))[:20]
    fp["login_like"] = sorted(set(re.findall(
        r"""["'`](/[\w/.\-]*(?:login|admin|manage|houtai)[\w/.\-]*)["'`]""", text, re.I)))[:15]
    report["findings"]["fingerprint"] = fp
    L += ["## 1. 站点指纹", "",
          "- 状态：%s｜Server：`%s`｜X-Powered-By：`%s`" % (st, fp["server"], fp["powered"]),
          "- 标题：%s" % (fp["title"] or "（无）"),
          "- 技术栈：%s" % (", ".join(fp["stack"]) or "未识别"),
          "- **平台特征：%s**" % (", ".join(fp["platform"]) or "未命中已知卡密系统"),
          "- 页面内 API 线索：%s" % (", ".join(fp["api_like"][:10]) or "无"),
          "- 页面内登录/后台线索：%s" % (", ".join(fp["login_like"][:10]) or "无"), ""]

    # 2) robots/sitemap
    for p in ("/robots.txt", "/sitemap.xml"):
        st2, h2, b2, _, _ = do(base + p)
        if st2 == 200 and b2:
            snip = b2.decode("utf-8", "replace")[:300]
            report["findings"].setdefault("robots", []).append({"path": p, "text": snip})
            L.append("- `%s` → 200，内容摘录：`%s`" % (p, snip.replace("\n", " ")[:150]))
    if report["findings"].get("robots"):
        L.append("")

    # 3) 后台路径
    if not args.no_admin and budget_ok():
        hits = []
        for p in ADMIN_PATHS:
            if not budget_ok():
                break
            st2, h2, b2, f2, e2 = do(base + p, method="HEAD")
            if st2 in (200, 301, 302, 401, 403):
                hit = {"path": p, "status": st2, "location": h2.get("Location", ""),
                       "server": h2.get("Server", "")}
                hits.append(hit)
        report["findings"]["admin_paths"] = hits
        L += ["## 2. 后台/登录路径探测", ""]
        if hits:
            L += ["| 路径 | 状态 | 跳转 |", "|---|---|---|"]
            for h in hits:
                L.append("| `%s` | %s | %s |" % (h["path"], h["status"], h["location"][:60]))
        else:
            L.append("（未命中；可加大字典或从客户端线索里拿真实后台路径）")
        L.append("")

    # 4) 泄漏文件
    if not args.no_leak and budget_ok():
        leaks = []
        for p in LEAK_FILES:
            if not budget_ok():
                break
            st2, h2, b2, f2, e2 = do(base + p)
            if st2 == 200 and b2:
                ct = h2.get("Content-Type", "")
                sig = ""
                head = b2[:400]
                if p.startswith("/.git"):
                    sig = "[git]" if b"repositoryformatversion" in b2 or b"ref:" in b2 else ""
                elif p.endswith((".zip", ".tar.gz")):
                    sig = "[zip]" if head[:2] == b"PK" else ""
                elif b"<?php" in head or b"DB_PASSWORD" in b2 or b"mysql" in b2.lower():
                    sig = "[php/db]"
                if sig or st2 == 200:
                    leaks.append({"path": p, "status": st2, "ctype": ct, "sig": sig,
                                  "size": len(b2), "preview": head[:200].decode("utf-8", "replace")})
        report["findings"]["leaks"] = leaks
        L += ["## 3. 泄漏文件探测", ""]
        if leaks:
            for lk in leaks:
                L.append("- **`%s` → 200** %s (%d bytes) %s" % (lk["path"], lk["sig"], lk["size"],
                                                               ("预览: `%s`" % lk["preview"][:120].replace("\n", " ")) if lk["sig"] else ""))
        else:
            L.append("（未命中）")
        L.append("")

    # 5) 下一步路由
    L += ["## 4. 下一步攻击面（按代价从低到高）", ""]
    fp = report["findings"].get("fingerprint", {})
    if report["findings"].get("leaks"):
        L.append("1. **泄漏文件已命中** → 优先吃：`.git` 用 git-dumper/GitHack 还原源码找后台逻辑与 DB 配置；"
                 "备份包解开找 `config.php`/`database.php` 里的**数据库账号密码**；phpinfo 拿绝对路径")
    L.append("2. **已知漏洞查证**：按 §1 的平台特征搜该平台历史漏洞（后台 SQLi / 任意文件读 / 上传）")
    if report["findings"].get("admin_paths"):
        L.append("3. **后台入口已定位**（上表）→ 观察登录逻辑：默认口令提示、验证码强度、是否 POST 明文、"
                 "响应差异（用户名枚举）；**在线爆破是最后手段**，需用户明确授权并设锁定线")
    L.append("4. **API 面**：客户端 API（/api/verify 等）常用弱鉴权 → 测越权/注入/返回体过大（可能带管理数据）")
    L.append("5. 拿到 hash 后：先识别类型（`hashid`/长度特征）→ hashcat 模式匹配 → 字典+规则；"
             "**不跑纯暴力**（见 Skill 禁令一）")
    L.append("")
    L.append("> 纪律：每步发现登记 E# 台账；在线动作低频；拿到凭证先验证最小权限再动数据。")

    md = os.path.join(out, "cardserver_recon.md")
    open(md, "w", encoding="utf-8").write("\n".join(L))
    json.dump(report, open(os.path.join(out, "cardserver_recon.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=2, default=str)
    print("[+] 报告 → %s（请求 %d/%d）" % (md, report["requests"], args.max_req))
    return 0


if __name__ == "__main__":
    sys.exit(main())
