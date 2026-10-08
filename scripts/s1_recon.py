#!/usr/bin/env python3
"""s1_recon.py - S1 分析一键侦察（建档 → 查壳 → 特征扫描 → 自动反编译 → 候选判定点 → 报告骨架）

为什么需要它：
    S1 原本是「人肉串工具」：手动建档、手动跑 packer_detect、手动跑 kami_scan、
    手动选反编译器、手动 grep 关键词。本脚本把它们串成一条命令，并且**强制走
    「指定软件优先」**（jadx CLI / idalib / radare2，而不是手搓兜底）。

用法:
    python s1_recon.py <目标文件或目录>                # 全流程
    python s1_recon.py target.apk --out work/mytarget  # 指定工作目录
    python s1_recon.py libfoo.so --fast                # 跳过反编译（只扫壳+特征+符号）

产出（默认 work/<目标名>/）:
    recon.md     —— 分析报告骨架（工具选型记录 / 壳结论 / 特征命中 / 候选判定点 / 下一步）
    recon.json   —— 结构化结果（可被后续脚本消费）
    jadx_out/    —— APK 反编译源码（jadx CLI 产出，供关键词定位）
    dex_list.txt / lib_list.txt 等中间件

判定点候选来源（按优先级）:
    APK : assets 伪装 ELF 自查 → jadx 源码关键词命中（文件:行）→ 未混淆类名/方法名
    ELF : .symtab 符号名命中（未 strip 时）→ strings 命中 → 动态符号导入特征
    PE  : strings 命中 → 导入表特征
"""

import argparse
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import zipfile
import shutil

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable

# 判定点关键词（名字命中 / 字符串命中）
KW_NAME = re.compile(
    r"(isvip|is_vip|ispro|ismember|isactive|isvalid|isexpired|islicensed|ispaid|"
    r"vip|expire|licen[sc]e|activ|auth|verif|check[_-]?(key|card|code|kami|licen)|"
    r"kami|cardkey|card_key|redeem|serial|trial|member|pay|order|"
    r"卡密|激活|授权|验证|会员|到期|试用)", re.I)
KW_STR = re.compile(
    r"(卡密|激活|授权|验证|会员|到期|试用|未授权|已过期|卡号|机器码|"
    r"kami|cardkey|license|licence|activate|activation|expire|trial|"
    r"not\s+authoriz|invalid\s+key|machine\s*code)", re.I)


def sh(cmd, timeout=1800, cwd=None):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd,
                           errors="replace")
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        return -9, "(超时)"
    except Exception as e:
        return -1, str(e)


def sha256(p, cap=256 * 1024 * 1024):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        while True:
            b = f.read(1024 * 1024)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def file_kind(p):
    with open(p, "rb") as f:
        head = f.read(8)
    if head[:4] == b"PK\x03\x04":
        # zip 家族：APK / jar / apks / 普通 zip
        try:
            with zipfile.ZipFile(p) as z:
                names = z.namelist()
            if "AndroidManifest.xml" in names:
                return "APK"
            if any(n.endswith(".dex") for n in names):
                return "JAR/APK(dex)"
            return "ZIP"
        except Exception:
            return "ZIP(坏)"
    if head[:4] == b"\x7fELF":
        return "ELF"
    if head[:2] == b"MZ":
        return "PE"
    if head[:4] == b"dex\n":
        return "DEX"
    if head[:5] in (b"<html", b"<!DOC"):
        return "HTML"
    if head[:3] == b"\xef\xbb\xbf":
        return "TEXT(utf8-bom)"
    return "UNKNOWN"


RUN_RE = re.compile(rb"[^\x00-\x08\x0b\x0c\x0e-\x1f\x7f]{4,}")


def extract_strings(data, min_len=5, limit=200000):
    """提取可打印串（ASCII + UTF-8/GB18030 中文；卡密目标必含中文串）。"""
    out = []
    for m in RUN_RE.finditer(data):
        raw = m.group()
        if len(raw) < min_len:
            continue
        s = None
        for enc in ("utf-8", "gb18030"):
            try:
                s = raw.decode(enc)
                break
            except UnicodeDecodeError:
                continue
        if s is None:
            s = raw.decode("latin-1")
        if sum(1 for c in s if c.isprintable()) < min_len:
            continue
        out.append((m.start(), s))
        if len(out) >= limit:
            break
    return out


def scan_strings_kw(pairs, kw, cap=60):
    hits = []
    for off, s in pairs:
        if kw.search(s):
            hits.append({"off": hex(off), "s": s[:160]})
            if len(hits) >= cap:
                break
    return hits


# ---------- ELF ----------
def elf_info(p):
    d = open(p, "rb").read()
    info = {"bits": 64 if d[4] == 2 else 32, "endian": "little" if d[5] == 1 else "big"}
    try:
        e_type, e_machine = struct.unpack_from("<HH", d, 16)
        info["type"] = {1: "REL", 2: "EXEC", 3: "DYN(PIE/so)", 4: "CORE"}.get(e_type, e_type)
        info["machine"] = {0x3e: "x86_64", 0xb7: "aarch64", 0x28: "arm", 0x03: "i386"}.get(e_machine, hex(e_machine))
        e_shoff, = struct.unpack_from("<Q", d, 0x28)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", d, 0x3a)
        secs = []
        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            sh_name, sh_type, _fl, sh_addr, sh_offset, sh_size, _lk, _inf, _al, _es = \
                struct.unpack_from("<IIQQQQIIQQ", d, off)
            secs.append(dict(nameoff=sh_name, type=sh_type, addr=sh_addr, off=sh_offset, size=sh_size, entsize=_es))
        shstr = b""
        if e_shstrndx < e_shnum:
            s = secs[e_shstrndx]
            shstr = d[s["off"]:s["off"] + s["size"]]
        for s in secs:
            end = shstr.find(b"\x00", s["nameoff"])
            s["name"] = shstr[s["nameoff"]:end].decode("utf-8", "replace") if shstr else ""
        info["sections"] = [(s["name"], s["size"]) for s in secs if s["name"]]
        # 符号
        def syms(secname, strname, entsize_expected=24):
            sec = next((s for s in secs if s["name"] == secname), None)
            st = next((s for s in secs if s["name"] == strname), None)
            if not sec or not st or not sec["size"]:
                return []
            strtab = d[st["off"]:st["off"] + st["size"]]
            res = []
            for i in range(sec["size"] // 24):
                off = sec["off"] + i * 24
                st_name, st_info, _o, st_shndx, st_value, st_size = struct.unpack_from("<IBBHQQ", d, off)
                if not st_name:
                    continue
                end = strtab.find(b"\x00", st_name)
                name = strtab[st_name:end].decode("utf-8", "replace")
                res.append((name, st_value, st_shndx, st_size))
            return res
        info["symtab"] = syms(".symtab", ".strtab")
        info["dynsyms"] = syms(".dynsym", ".dynstr")
    except Exception as e:
        info["parse_error"] = str(e)
    return info, d


# ---------- PE ----------
def pe_info(p):
    d = open(p, "rb").read()
    info = {}
    try:
        pe = struct.unpack_from("<I", d, 0x3c)[0]
        machine = struct.unpack_from("<H", d, pe + 4)[0]
        info["machine"] = {0x8664: "x86_64", 0x14c: "i386", 0xaa64: "aarch64"}.get(machine, hex(machine))
        nsec = struct.unpack_from("<H", d, pe + 6)[0]
        opt_size = struct.unpack_from("<H", d, pe + 20)[0]
        secoff = pe + 24 + opt_size
        secs = []
        for i in range(nsec):
            off = secoff + i * 40
            name = d[off:off + 8].rstrip(b"\x00").decode("ascii", "replace")
            vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", d, off + 8)
            secs.append(dict(name=name, vsize=vsize, rawsize=rawsize, rawptr=rawptr))
        info["sections"] = [(s["name"], s["rawsize"]) for s in secs]
    except Exception as e:
        info["parse_error"] = str(e)
    return info, d


# ---------- APK ----------
def apk_info(p):
    info = {"dex": [], "libs": [], "assets_suspect": [], "other": []}
    with zipfile.ZipFile(p) as z:
        for i in z.infolist():
            n = i.filename
            if n.endswith(".dex"):
                info["dex"].append((n, i.file_size))
            elif n.startswith("lib/") and n.endswith(".so"):
                info["libs"].append((n, i.file_size))
            elif n.startswith("assets/"):
                # 1.2b 强制自查：assets 下的伪装 ELF / 加密 sh
                try:
                    head = z.read(n)[:16] if i.file_size < 60 * 1024 * 1024 else z.open(n).read(16)
                except Exception:
                    head = b""
                if head[:4] == b"\x7fELF":
                    info["assets_suspect"].append((n, i.file_size, "ELF（伪装二进制，卡密判定可能在这里！）"))
                elif head[:2] == b"#!":
                    info["assets_suspect"].append((n, i.file_size, "shell 脚本"))
                elif head and not head[:1].isascii() or (head[:1] not in (b"", b"{", b"[", b"<")):
                    # 高熵/十六进制开头的文本 → 疑似加密脚本（RX/ZF 家族）
                    try:
                        sample = z.read(n)[:200] if i.file_size < 60 * 1024 * 1024 else b""
                    except Exception:
                        sample = b""
                    if sample and re.match(rb"^[0-9a-fA-F\s]{120,}$", sample):
                        info["assets_suspect"].append((n, i.file_size, "疑似加密 sh（hex 开头，试 scripts/sh_unpeel.py）"))
                else:
                    info["assets_suspect"].append((n, i.file_size, "其它 assets 大文件"))
    return info


NOISE_PKG = re.compile(
    r"^(android|androidx|com/android|com/google|kotlin|kotlinx|org/|javax|java/|"
    r"com/facebook|okhttp3|retrofit2|okio|io/reactivex|dagger|com/squareup|"
    r"org/json|com/bumptech|com/airbnb|com/blankj|com/scwang|com/github)",
    re.I)


def detect_app_pkg(jout, apk):
    """拿目标 APK 自己的包名（优先 androguard，回退找 MainActivity）。"""
    try:
        from androguard.core.apk import APK as AG
        pkg = AG(apk).get_package()
        if pkg:
            return pkg
    except Exception:
        pass
    src = os.path.join(jout, "sources")
    for dp, dns, fns in os.walk(src):
        if "MainActivity.java" in fns:
            return os.path.relpath(dp, src).replace("\\", ".").replace("/", ".")
    return None


def score_java_hit(h, app_pfx):
    """候选判定点打分：应用自身包/方法定义/中文关键词加权，内置库降权。"""
    sc = 1
    fp = h["file"].replace("\\", "/")
    if fp.startswith("sources/"):
        fp = fp[len("sources/"):]
    text = h["text"]
    if re.search(r"(public|private|protected|final).*\w+\s*\(", text):
        sc += 3                      # 方法/构造定义
    if app_pfx and fp.startswith(app_pfx):
        sc += 8                      # 目标应用自己的代码
    if re.search(r"(kami|card|vip|verif|auth|licen[sc]e|activ|expire|order|pay)", fp, re.I):
        sc += 2                      # 文件名本身带语义
    if re.search(r"[\u5361\u5bc6\u6fc0\u6d3b\u6388\u6743\u9a8c\u8bc1\u4f1a\u5458\u5230\u671f\u8bd5\u7528]", text):
        sc += 5                      # 中文业务词
    if NOISE_PKG.match(fp):
        sc -= 10                     # 内置库（apksig/androidx/…）
    return sc


def resolve_jadx(tools):
    """从盘点结果解析 jadx CLI 调用方式（优先 CLI，其次 jar）。返回命令前缀列表。"""
    import shutil
    cands = []
    for k, v in tools.items():
        if "jadx" in k.lower():
            cands.append(str(v))
    expanded = []
    for c in cands:
        lc = c.lower()
        if lc.endswith((".bat", ".exe", ".jar")):
            expanded.append(c)
            continue
        if os.path.isdir(c):
            for rel in (r"bin\jadx.bat", r"bin\jadx", r"jadx.bat", r"jadx",
                        r"bin\jadx-gui.bat", r"jadx-gui-launch.bat",
                        r"lib\jadx-gui-1.5.5-all.jar"):
                p2 = os.path.join(c, rel)
                if os.path.exists(p2):
                    expanded.append(p2)
            # 同级目录（tools\jadx-gui 旁边常有 tools\jadx CLI）
            parent = os.path.dirname(os.path.abspath(c))
            for sib in ("jadx", "jadx-cli"):
                for rel in (r"bin\jadx.bat", r"bin\jadx"):
                    p2 = os.path.join(parent, sib, rel)
                    if os.path.exists(p2):
                        expanded.append(p2)
    expanded += [
        r"C:\Users\Administrator\tools\jadx\bin\jadx.bat",
        os.path.join(os.path.expanduser("~"), "tools", "jadx", "bin", "jadx.bat"),
    ]
    w = shutil.which("jadx")
    if w:
        expanded.append(w)
    # 优先级：CLI bat/exe > 其它 bat > jar(lib 里可能是 GUI jar，勿用于 CLI)
    for c in expanded:
        if c.lower().endswith(("jadx.bat", "jadx.exe")) and os.path.exists(c):
            return [c]
    for c in expanded:
        if c.lower().endswith(".bat") and os.path.exists(c):
            return [c]
    for c in expanded:
        if c.lower().endswith(".jar") and "cli" in c.lower() and os.path.exists(c):
            return ["java", "-jar", c]
    return None


def find_ida_repo():
    """从 ZCode MCP 注册表找 ida-pro-mcp 的 uv 项目目录。"""
    cfg = os.path.join(os.path.expanduser("~"), ".zcode", "cli", "config.json")
    try:
        d = json.load(open(cfg, encoding="utf-8"))
        for name in ("idalib-mcp", "ida-pro-mcp"):
            e = (d.get("mcp") or {}).get("servers", {}).get(name)
            if not e:
                continue
            args = e.get("args", [])
            if "--directory" in args:
                return args[args.index("--directory") + 1]
    except Exception:
        pass
    return None


def run_idalib(t, out, rec, cand, args, step):
    """调用 idalib_probe.py（官方无头 IDA）在 stripped 目标里找候选判定点。"""
    if getattr(args, "fast", False):
        rec["notes"].append("--fast：跳过 idalib 深挖（stripped 目标建议不跳）")
        return
    if os.path.getsize(t) > 300 * 1024 * 1024:
        rec["notes"].append("目标 >300MB，跳过 idalib 自动深挖（可手动跑 idalib_probe.py）")
        return
    repo = find_ida_repo()
    probe = os.path.join(HERE, "idalib_probe.py")
    if not repo or not os.path.exists(probe):
        rec["notes"].append("找不到 ida-pro-mcp 项目目录，跳过 idalib 深挖")
        return
    cmd = ["uv", "run", "--project", repo, "python", probe, os.path.abspath(t),
           os.path.abspath(out), "--top", "6"]
    rc, o = sh(cmd, timeout=900)
    try:
        j = json.load(open(os.path.join(out, "idalib.json"), encoding="utf-8"))
    except Exception:
        j = None
    if j and j.get("ok"):
        rec["idalib"] = j
        if j.get("candidates"):
            cand["idalib"] = j["candidates"]
        step("idalib 深挖(IDA)", True, "函数 %s | 关键词串 %d | 候选 %d | 伪代码 %d 份"
             % (j.get("funcs"), len(j.get("kw_strings", [])), len(j.get("candidates", [])),
                len(j.get("decomp", []))))
        if j.get("decomp"):
            rec["notes"].append("候选函数伪代码已落盘 decomp/ —— 直接读这些 .c 定位判定点")
    else:
        step("idalib 深挖(IDA)", False, ((j or {}).get("error") or o.strip().splitlines()[-1] if o.strip() else "失败")[:160])


def prepare_out(target, out_arg):
    base = os.path.basename(os.path.normpath(target))
    name = os.path.splitext(base)[0]
    out = out_arg or os.path.join("work", name)
    os.makedirs(out, exist_ok=True)
    return out


def main():
    ap = argparse.ArgumentParser(description="S1 一键侦察（建档→查壳→特征→反编译→候选点→报告）")
    ap.add_argument("target")
    ap.add_argument("--out", help="工作目录（默认 work/<目标名>）")
    ap.add_argument("--fast", action="store_true", help="跳过反编译（只做扫描与符号）")
    ap.add_argument("--top", type=int, default=40, help="每类候选点上限（默认 40）")
    args = ap.parse_args()

    t = args.target
    if not os.path.exists(t):
        print("[-] 目标不存在:", t)
        return 2
    out = prepare_out(t, args.out)
    rec = {"target": os.path.abspath(t), "out": out, "steps": [], "candidates": {},
           "notes": []}

    def step(name, ok, detail=""):
        rec["steps"].append({"name": name, "ok": ok, "detail": detail})
        print("%s [%s] %s %s" % ("[+]" if ok else "[-]", name, "OK" if ok else "FAIL", detail))

    # 0) 工具盘点（选型依据）
    inv_py = os.path.join(HERE, "tool_inventory.py")
    tools = {}
    rc, outj = sh([PY, inv_py, "--quiet", "--json", os.path.join(out, "tools.json")], timeout=180)
    try:
        inv = json.load(open(os.path.join(out, "tools.json"), encoding="utf-8"))
        for g, es in inv["groups"].items():
            for e in es:
                if e["found"]:
                    tools[e["name"]] = e["path"]
    except Exception:
        pass
    step("tool_inventory", bool(tools), "可用工具 %d 项" % len(tools))

    # 1) 建档
    size = os.path.getsize(t)
    kind = file_kind(t)
    digest = sha256(t) if size < 512 * 1024 * 1024 else "(>512MB 跳过)"
    rec.update(size=size, kind=kind, sha256=digest)
    step("建档", True, "%s | %d bytes | %s" % (kind, size, digest[:16]))

    # 2) 壳检测
    pd_py = os.path.join(HERE, "packer_detect.py")
    rc, o = sh([PY, pd_py, t, "--json", os.path.join(out, "packer.json")], timeout=900)
    step("packer_detect", rc == 0, "" if rc == 0 else o.strip().splitlines()[-1][:120] if o.strip() else "")
    try:
        rec["packer"] = json.load(open(os.path.join(out, "packer.json"), encoding="utf-8"))
    except Exception:
        rec["packer"] = None

    # 3) 卡密特征扫描
    ks_py = os.path.join(HERE, "kami_scan.py")
    rc, o = sh([PY, ks_py, t, "--json", os.path.join(out, "kami.json"), "--top", str(args.top)], timeout=900)
    step("kami_scan", rc == 0, "" if rc == 0 else "见 kami.json")
    try:
        rec["kami"] = json.load(open(os.path.join(out, "kami.json"), encoding="utf-8"))
    except Exception:
        rec["kami"] = None

    cand = rec["candidates"]

    # 4) 类型专属深挖
    if kind == "APK":
        ai = apk_info(t)
        rec["apk"] = ai
        step("APK 结构", True, "dex=%d libs=%d assets疑点=%d"
             % (len(ai["dex"]), len(ai["libs"]), len(ai["assets_suspect"])))
        if ai["assets_suspect"]:
            rec["notes"].append("assets 有 %d 个疑点文件 —— **S1.2b 强制自查**：优先按伪装 ELF/加密 sh 处理（见 references/apk-embedded-binary-cardkey.md）" % len(ai["assets_suspect"]))
        # jadx 反编译（指定软件优先）
        jadx_cmd = resolve_jadx(tools)
        if jadx_cmd and not args.fast:
            jout = os.path.join(out, "jadx_out")
            cmd = list(jadx_cmd) + ["-d", jout, "--no-res", "--show-bad-code", t]
            rc, o = sh(cmd, timeout=3600)
            n_java = 0
            ok = os.path.isdir(jout)
            if ok:
                n_java = sum(1 for _, _, fs in os.walk(jout) for f in fs if f.endswith(".java"))
                ok = n_java > 0
            step("jadx 反编译", ok, ("%s（%d 个 .java）" % (jout, n_java)) if ok
                 else "见控制台；可改用 jadx-gui + jadx-mcp")
            if ok:
                # 关键词定位（候选判定点）
                hits = []
                pat = KW_NAME
                for dp, dns, fns in os.walk(jout):
                    for fn in fns:
                        if not fn.endswith((".java", ".kt", ".smali")):
                            continue
                        fp = os.path.join(dp, fn)
                        try:
                            if os.path.getsize(fp) > 4 * 1024 * 1024:
                                continue
                            txt = open(fp, encoding="utf-8", errors="ignore").read()
                        except Exception:
                            continue
                        for m in pat.finditer(txt):
                            ln = txt.count("\n", 0, m.start()) + 1
                            line = txt.splitlines()[ln - 1].strip()[:120]
                            hits.append({"file": os.path.relpath(fp, jout), "line": ln,
                                         "kw": m.group(), "text": line})
                # 应用包 + 打分排序（库降权、业务包加权、中文词加权）
                app_pkg = detect_app_pkg(jout, t)
                app_pfx = app_pkg.replace(".", "/") if app_pkg else None
                rec["app_package"] = app_pkg
                seen = set()
                dedup = []
                for h in hits:
                    key = (h["file"], h["line"])
                    if key in seen:
                        continue
                    seen.add(key)
                    h["score"] = score_java_hit(h, app_pfx)
                    dedup.append(h)
                dedup.sort(key=lambda x: -x["score"])
                # 每个文件最多 4 条，避免单文件刷屏
                per_file = {}
                picked = []
                for h in dedup:
                    c = per_file.get(h["file"], 0)
                    if c >= 4:
                        continue
                    per_file[h["file"]] = c + 1
                    picked.append(h)
                    if len(picked) >= args.top:
                        break
                cand["java"] = picked
                step("候选判定点(java)", bool(picked),
                     "命中 %d 条 → 打分排序后取前 %d（应用包：%s）" % (len(dedup), len(picked), app_pkg or "未识别"))
        else:
            step("jadx 反编译", False, "jadx 未装或 --fast；APK 可用 jadx-mcp（GUI）或装 jadx CLI")

    elif kind in ("ELF",):
        ei, d = elf_info(t)
        rec["elf"] = {"bits": ei.get("bits"), "type": ei.get("type"), "machine": ei.get("machine"),
                      "sections": ei.get("sections", [])[:30],
                      "symtab_n": len(ei.get("symtab", [])), "dynsym_n": len(ei.get("dynsyms", []))}
        step("ELF 解析", True, "%s %s | symtab=%d dynsym=%d"
             % (ei.get("machine"), ei.get("type"), len(ei.get("symtab", [])), len(ei.get("dynsyms", []))))
        # 符号候选
        if ei.get("symtab"):
            cand["elf_syms"] = [{"name": n, "addr": hex(v), "size": sz}
                                for (n, v, x, sz) in ei["symtab"] if x != 0 and KW_NAME.search(n)][:args.top]
            step("候选函数(符号表)", True, "%d 个命中" % len(cand.get("elf_syms", [])))
        # strings
        pairs = extract_strings(d)
        rec["strings_n"] = len(pairs)
        cand["elf_strings"] = scan_strings_kw(pairs, KW_STR, cap=args.top)
        step("候选字符串", bool(cand["elf_strings"]), "%d 条命中 / 共 %d 串" % (len(cand["elf_strings"]), len(pairs)))
        # 网络迹象（1.3a 排除法辅助）
        NET_RE = re.compile(r"https?://\S+|/api/[a-z]|\.php\b|[\"']token[\"']|\bsign=|\bmsToken\b")
        net_hits = [s for _, s in pairs if NET_RE.search(s)][:20]
        rec["net_evidence"] = net_hits
        if net_hits:
            step("网络迹象", True, "发现 %d 条 URL/API 串（B/C 类线索）" % len(net_hits))
        # idalib 深挖（指定软件优先：stripped 也能找判定点）
        if any("idalib" in k.lower() for k in tools):
            run_idalib(t, out, rec, cand, args, step)

    elif kind == "PE":
        pi, d = pe_info(t)
        rec["pe"] = pi
        step("PE 解析", True, "%s | 节=%s" % (pi.get("machine"), [s[0] for s in pi.get("sections", [])][:8]))
        pairs = extract_strings(d)
        cand["pe_strings"] = scan_strings_kw(pairs, KW_STR, cap=args.top)
        step("候选字符串", bool(cand["pe_strings"]), "%d 条命中" % len(cand["pe_strings"]))
        if any("ida" in k.lower() for k in tools):
            run_idalib(t, out, rec, cand, args, step)

    elif kind in ("ZIP", "JAR/APK(dex)"):
        with zipfile.ZipFile(t) as z:
            rec["zip_entries"] = len(z.namelist())
        step("ZIP 结构", True, "%d 条目" % rec["zip_entries"])

    elif os.path.isdir(t):
        # Web 目录 / 解包目录
        ws = os.path.join(HERE, "web_kami_scan.py")
        if os.path.exists(ws):
            rc, o = sh([PY, ws, t, "--json", os.path.join(out, "web.json")], timeout=900)
            step("web_kami_scan", rc == 0, "")
            try:
                rec["web"] = json.load(open(os.path.join(out, "web.json"), encoding="utf-8"))
            except Exception:
                rec["web"] = None

    # 5) 写报告
    lines = []
    lines.append("# S1 分析报告：%s" % os.path.basename(t))
    lines.append("")
    lines.append("> 由 `scripts/s1_recon.py` 自动生成（%s）。**人工必须复核并补齐分析与假设（E# 台账）。**" % __import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M"))
    lines.append("")
    lines.append("## 0. 工具选型记录（指定软件优先）")
    for k in sorted(tools.keys()):
        lines.append("- %s" % k)
    lines.append("")
    lines.append("## 1. 建档")
    lines.append("- 路径：`%s`" % rec["target"])
    lines.append("- 大小：%d bytes（%.1f MB）" % (size, size / 1048576))
    lines.append("- 类型：**%s**" % kind)
    lines.append("- SHA256：`%s`" % digest)
    lines.append("")
    lines.append("## 2. 壳 / 对抗层结论")
    if rec.get("packer"):
        lines.append("```json")
        lines.append(json.dumps(rec["packer"], ensure_ascii=False, indent=1)[:2000])
        lines.append("```")
    else:
        lines.append("（packer_detect 无输出，人工判断）")
    lines.append("")
    lines.append("## 3. 卡密特征命中")
    if rec.get("kami"):
        lines.append("```json")
        lines.append(json.dumps(rec["kami"], ensure_ascii=False, indent=1)[:2500])
        lines.append("```")
    else:
        lines.append("（kami_scan 无输出）")
    lines.append("")

    if kind == "APK" and rec.get("apk"):
        ai = rec["apk"]
        lines.append("## 4. APK 结构")
        lines.append("- dex：%s" % ", ".join("%s(%.1fMB)" % (n, s / 1048576) for n, s in ai["dex"]))
        lines.append("- native libs：%s" % ", ".join("%s(%.1fMB)" % (n, s / 1048576) for n, s in ai["libs"][:20]))
        lines.append("")
        lines.append("### assets 疑点（S1.2b 强制自查项）")
        for n, s, why in ai["assets_suspect"][:30]:
            lines.append("- `%s`（%.1f KB）— %s" % (n, s / 1024, why))
        lines.append("")

    if cand.get("java"):
        lines.append("## 5. 候选判定点（jadx 关键词命中 + 打分排序，应用包：%s）"
                     % (rec.get("app_package") or "未识别"))
        lines.append("")
        lines.append("> 打分规则：应用自身包 +8 / 方法定义 +3 / 中文业务词 +5 / 文件名语义 +2 / 内置库 -10")
        lines.append("")
        for h in cand["java"]:
            lines.append("- [%d分] `%s:%d` `%s`" % (h.get("score", 0), h["file"], h["line"], h["text"]))
        lines.append("")
    if cand.get("elf_syms"):
        lines.append("## 5. 候选函数（符号表命中）")
        for h in cand["elf_syms"]:
            lines.append("- `%s` @ %s (size=%d)" % (h["name"], h["addr"], h["size"]))
        lines.append("")
    if cand.get("idalib"):
        lines.append("## 5. 候选函数（IDA 无头分析：关键词串 xref 回溯）")
        for c in cand["idalib"]:
            lines.append("- `%s` @ %s — 关联关键词串 %d 条：%s" % (
                c["name"], c["ea"], c["n_kw_strings"], "; ".join(c["strings"][:3])))
            if c.get("decomp_file"):
                lines.append("  - 伪代码：`%s`" % c["decomp_file"])
        lines.append("")
    if cand.get("elf_strings") or cand.get("pe_strings"):
        key = "elf_strings" if cand.get("elf_strings") else "pe_strings"
        lines.append("## 5. 候选字符串")
        for h in cand[key]:
            lines.append("- %s `%s`" % (h["off"], h["s"]))
        lines.append("")
    if rec.get("net_evidence"):
        lines.append("## 6. 网络迹象（B/C 类线索，配合 1.3a 五项排除法）")
        for s in rec["net_evidence"]:
            lines.append("- `%s`" % s)
        lines.append("")

    lines.append("## 7. 下一步建议")
    if rec["notes"]:
        for n in rec["notes"]:
            lines.append("- %s" % n)
    if cand.get("java"):
        lines.append("- 用 `smali_kami_patch.py` 对候选类做 dry-run 定位；改前先在 jadx 确认调用链")
    if cand.get("elf_syms"):
        lines.append("- 用 `elf_patch.py --func <名>` 或 `emu_check.py --sym <名>` 做门控定位/差分验证")
    if kind == "APK":
        lines.append("- 产出物走 `s4_pipeline.py`（回编→对齐→签名→验证），别手工拼顺序")
    lines.append("")
    lines.append("## 8. E# 假设台账（人工填写）")
    lines.append("| E# | 假设 | 依据 | 验证方式 | 状态 |")
    lines.append("|---|---|---|---|---|")
    lines.append("| E1 |  |  |  | 待验证 |")
    lines.append("")

    md = os.path.join(out, "recon.md")
    open(md, "w", encoding="utf-8").write("\n".join(lines))
    json.dump(rec, open(os.path.join(out, "recon.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=2, default=str)
    step("产出报告", True, md)

    print("\n" + "=" * 60)
    print("侦察完成 → %s" % md)
    print("候选判定点：java=%d elf_syms=%d strings=%d"
          % (len(cand.get("java", [])), len(cand.get("elf_syms", [])),
             len(cand.get("elf_strings", []) or cand.get("pe_strings", []))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
