#!/usr/bin/env python3
"""kami_scan.py - 卡密/授权验证特征静态扫描器。

用法:
    python kami_scan.py <target> [--top N] [--json out.json] [--max-files N] [--max-size MB]

target 可以是:
    - APK / ZIP  (遍历内部 dex、so、xml、arsc)
    - DEX / SO / EXE / DLL 等单文件二进制
    - 已解包目录 (smali / java / xml / json / so 等)

输出按特征分组统计与 top 候选(文件:偏移 或 文件:行号)，供 S1 定位判定点。
"""

import argparse
import hashlib
import json
import os
import re
import sys
import zipfile

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# ---------------------------------------------------------------- 特征库

PATTERNS = {
    "cardkey": [
        r"card[-_ ]?key", r"cd[-_ ]?key", r"kami", r"ka[-_ ]?mi",
        r"activation[-_ ]?code", r"activate[-_ ]?(code|key)", r"active[-_ ]?code",
        r"license[-_ ]?(key|code|check|valid)", r"licence[-_ ]?key",
        r"serial[-_ ]?(number|no|key)", r"reg(ister)?[-_ ]?code",
        r"auth[-_ ]?code", r"invite[-_ ]?code", r"redeem[-_ ]?code",
    ],
    "verify": [
        r"check[-_ ]?(license|auth|valid|activation|key|vip|member)",
        r"(license|auth|key|vip|member)[-_ ]?check",
        r"verif(y|ied|ication)", r"is[-_ ]?(valid|activated|licensed|vip|pro|member)",
        r"validate", r"authenticate",
        r"expire(d|s|_time|-time)?", r"expir(y|ation)",
        r"trial", r"remaining[-_ ]?(days|time|count)", r"days[-_ ]?left",
        r"unauthorized", r"not[-_ ]?activated", r"invalid[-_ ]?(key|code|license)",
        r"授权", r"激活", r"未授权", r"已过期", r"卡密", r"到期", r"试用",
    ],
    "network": [
        r"https?://[A-Za-z0-9.\-]{3,}",
        r"/api/[A-Za-z0-9_\-/]{0,60}(auth|license|active|activate|verify|check|register|card|key|vip|member)[A-Za-z0-9_\-/]{0,40}",
        r"(verify|check|activate|auth|license)[-_ ]?(url|api|host|server|endpoint)",
    ],
    "storage": [
        r"SharedPreferences", r"getSharedPreferences", r"PreferenceManager",
        r"SOFTWARE\\[A-Za-z0-9_\\ ]{2,60}", r"HKEY_[A-Z_]+",
        r"(license|auth|activate|vip|expire)[-_ ]?(file|dat|cfg|conf|xml|json|bin|key)",
        r"getFilesDir|getExternalFilesDir|Environment\.getExternalStorage",
    ],
    "crypto": [
        r"\bAES\b", r"\bDES\b", r"\bRSA\b", r"\bMD5\b", r"\bSHA[-_]?(1|256|512)?\b",
        r"\bHMAC\b", r"\bBase64\b", r"\bCRC32?\b", r"MessageDigest", r"Cipher",
        r"SecretKeySpec", r"javax\.crypto", r"openssl|mbedtls|CryptEncrypt|BCrypt",
    ],
    "time": [
        r"System\.currentTimeMillis", r"System\.nanoTime", r"Calendar\.getInstance",
        r"SimpleDateFormat", r"\btime\(NULL\)|\btime\(0\)", r"GetSystemTime",
        r"GetLocalTime", r"QueryPerformanceCounter", r"Date\(\)",
    ],
    "native": [
        r"System\.loadLibrary", r"System\.load\(", r"dlopen", r"dlsym",
        r"JNI_OnLoad", r"RegisterNatives", r"GetProcAddress", r"LoadLibrary",
    ],
    "packer": [
        r"lib(dog|jiagu|bangcle|secshell|ijiami|nqshield|exec|shell|protect)[A-Za-z0-9_]*\.so",
        r"(qihoo|360|tencent|ali|baidu)[-_ ]?(jiagu|legu|sec|shell|protect)",
        r"(dex|payload|shell)[-_ ]?(protect|加密|加固)",
        r"\.vmp\.", r"VMProtect", r" Themida", r" UPX", r" ASPack", r" Enigma",
    ],
}

COMPILED = {}
for _g, _ps in PATTERNS.items():
    COMPILED[_g] = [re.compile(p, re.IGNORECASE) for p in _ps]

TEXT_EXT = {
    ".smali", ".java", ".kt", ".xml", ".json", ".txt", ".js", ".ts",
    ".properties", ".yml", ".yaml", ".gradle", ".py", ".c", ".cpp", ".h",
}
BIN_EXT = {".dex", ".so", ".exe", ".dll", ".elf", ".bin", ".o", ".a", ".sys", ".arsc"}


# ---------------------------------------------------------------- 提取

def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def iter_strings(data, min_len=4):
    """yield (offset, text) for ASCII and UTF-16LE printable runs."""
    ascii_re = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    for m in ascii_re.finditer(data):
        yield m.start(), m.group().decode("ascii", "ignore")
    u16_re = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)
    seen = set()
    for m in u16_re.finditer(data):
        if m.start() - 1 in seen:
            continue
        seen.add(m.start())
        yield m.start(), m.group().decode("utf-16-le", "ignore")


def scan_bytes(data, rel, hits, min_len):
    """二进制：按提取出的字符串匹配。"""
    for off, text in iter_strings(data, min_len):
        for group, regs in COMPILED.items():
            for reg in regs:
                m = reg.search(text)
                if m:
                    hits[group].append({"loc": rel, "pos": hex(off),
                                        "hit": m.group(0)[:80], "ctx": text[:120]})
                    break
            else:
                continue
            break


def scan_text(text, rel, hits):
    """文本：按行匹配，记录行号。"""
    for lineno, line in enumerate(text.splitlines(), 1):
        if len(line) > 4000:
            line = line[:4000]
        for group, regs in COMPILED.items():
            for reg in regs:
                m = reg.search(line)
                if m:
                    hits[group].append({"loc": rel, "pos": "L%d" % lineno,
                                        "hit": m.group(0)[:80],
                                        "ctx": line.strip()[:160]})
                    break
            else:
                continue
            break


def scan_apk(path, hits, args):
    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
        interesting = [n for n in names
                       if os.path.splitext(n)[1].lower() in (BIN_EXT | TEXT_EXT)
                       or n.endswith("AndroidManifest.xml")
                       or n.endswith("resources.arsc")]
        for n in interesting[: args.max_files]:
            info = zf.getinfo(n)
            if info.file_size > args.max_size * 1024 * 1024:
                continue
            try:
                data = zf.read(n)
            except Exception as e:
                hits["_errors"].append({"loc": n, "pos": "-", "hit": "read failed",
                                        "ctx": str(e)[:120]})
                continue
            ext = os.path.splitext(n)[1].lower()
            if ext in TEXT_EXT:
                scan_text(data.decode("utf-8", "ignore"), "apk:%s" % n, hits)
            else:
                scan_bytes(data, "apk:%s" % n, hits, args.min_len)
    return len(interesting)


def scan_dir(root, hits, args):
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not d.startswith((".git", "node_modules", "build"))]
        for fn in filenames:
            if count >= args.max_files:
                return count
            p = os.path.join(dirpath, fn)
            ext = os.path.splitext(fn)[1].lower()
            if ext not in (TEXT_EXT | BIN_EXT):
                continue
            try:
                if os.path.getsize(p) > args.max_size * 1024 * 1024:
                    continue
                if ext in TEXT_EXT:
                    with open(p, "r", encoding="utf-8", errors="ignore") as f:
                        scan_text(f.read(), os.path.relpath(p, root), hits)
                else:
                    with open(p, "rb") as f:
                        scan_bytes(f.read(), os.path.relpath(p, root), hits, args.min_len)
            except Exception as e:
                hits["_errors"].append({"loc": os.path.relpath(p, root), "pos": "-",
                                        "hit": "read failed", "ctx": str(e)[:120]})
            count += 1
    return count


def scan_file(path, hits, args):
    ext = os.path.splitext(path)[1].lower()
    if ext in TEXT_EXT:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            scan_text(f.read(), os.path.basename(path), hits)
    else:
        with open(path, "rb") as f:
            scan_bytes(f.read(), os.path.basename(path), hits, args.min_len)


# ---------------------------------------------------------------- 主流程

def main():
    ap = argparse.ArgumentParser(description="卡密/授权验证特征静态扫描")
    ap.add_argument("target", help="APK / ZIP / 二进制文件 / 解包目录")
    ap.add_argument("--top", type=int, default=10, help="每组显示条数，默认 10")
    ap.add_argument("--json", dest="json_out", help="结果写入 JSON 文件")
    ap.add_argument("--max-files", type=int, default=400, help="最多扫描文件数")
    ap.add_argument("--max-size", type=int, default=200, help="单文件上限 MB")
    ap.add_argument("--min-len", type=int, default=4, help="字符串最小长度")
    args = ap.parse_args()

    target = args.target
    if not os.path.exists(target):
        print("[-] target not found: %s" % target)
        return 2

    hits = {g: [] for g in PATTERNS}
    hits["_errors"] = []

    print("[+] target: %s" % target)
    if os.path.isfile(target):
        print("[+] size  : %d bytes" % os.path.getsize(target))
        print("[+] sha256: %s" % sha256_of(target))
        try:
            with zipfile.ZipFile(target) as _:
                is_zip = True
        except Exception:
            is_zip = False
        if is_zip:
            n = scan_apk(target, hits, args)
            print("[+] type  : APK/ZIP (%d entries scanned)" % n)
        else:
            scan_file(target, hits, args)
            print("[+] type  : file")
    else:
        n = scan_dir(target, hits, args)
        print("[+] type  : dir (%d files scanned)" % n)

    total = sum(len(v) for k, v in hits.items() if not k.startswith("_"))
    print("[+] total hits: %d\n" % total)

    out = {}
    for group in PATTERNS:
        items = hits[group]
        out[group] = items
        if not items:
            continue
        print("== %-8s (%d hits)" % (group, len(items)))
        for it in items[: args.top]:
            print("   %-46s %-10s | %s" % (it["loc"][:46], it["pos"], it["hit"][:60]))
        if len(items) > args.top:
            print("   ... %d more" % (len(items) - args.top))
        print()

    if hits["_errors"]:
        print("== errors (%d)" % len(hits["_errors"]))
        for it in hits["_errors"][:5]:
            print("   %s: %s" % (it["loc"], it["ctx"]))

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump({"target": target, "hits": out,
                       "errors": hits["_errors"]}, f, ensure_ascii=False, indent=2)
        print("\n[+] json written: %s" % args.json_out)

    if total == 0:
        print("[-] 无命中：样本可能加壳/字符串加密，转 S1 动态确认或先脱壳。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
