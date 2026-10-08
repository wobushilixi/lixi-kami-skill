#!/usr/bin/env python3
"""smali_kami_patch.py - smali 卡密判定点定位与补丁生成。

用法:
    # 只列出候选(默认 dry-run，不写文件)
    python smali_kami_patch.py <smali目录|smali文件> [--keywords k1,k2] [--top N]

    # 生成补丁并写回(自动备份 .bak)
    python smali_kami_patch.py <smali目录> --apply --ret true [--limit 5]

    # 只处理布尔返回值方法，且方法名必须含 activate
    python smali_kami_patch.py <smali目录> --apply --ret true --keywords activate,vip

补丁规则:
    - 返回类型 Z(布尔): 插 const/4 v0, 0x1(true) 或 0x0(false) + return v0
    - 返回类型 I      : 插 const/4 v0, 0xN(--int-value，默认 0) + return v0
    - 返回 V/对象     : 不直接 patch，仅报告，需改调用点或改比较指令
    - 寄存器不足时自动把 .locals N 提到 N+1(.registers 同理)
"""

import argparse
import os
import re
import shutil
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

DEFAULT_KEYWORDS = [
    "license", "licence", "auth", "activate", "activation", "active",
    "verify", "valid", "kami", "cardkey", "cdkey", "card", "key",
    "vip", "member", "pro", "expire", "expired", "trial", "redeem",
    "register", "regist", "check", "pay", "order", "serial",
]

METHOD_RE = re.compile(r"^\.method\s+(.*)$")
END_METHOD_RE = re.compile(r"^\.end\s+method\s*$")
LOCALS_RE = re.compile(r"^\s*\.(locals|registers)\s+(\d+)")
RET_TYPE_RE = re.compile(r"^\s*\.method.*\)\s*(\S+)\s*$")


def parse_smali(path):
    """返回 [(class_name, method_sig, ret_type, body_start_idx, lines)]"""
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.read().splitlines()

    cls = ""
    for ln in lines:
        if ln.startswith(".class"):
            cls = ln.strip()
            break

    out = []
    i = 0
    while i < len(lines):
        m = METHOD_RE.match(lines[i])
        if m:
            sig = m.group(1).strip()
            rt = ""
            rm = RET_TYPE_RE.match(lines[i])
            if rm:
                rt = rm.group(1)
            start = i
            j = i + 1
            while j < len(lines) and not END_METHOD_RE.match(lines[j]):
                j += 1
            out.append((cls, sig, rt, start, j, lines[start:j + 1]))
            i = j
        i += 1
    return out


def hit_keywords(sig, body, keywords):
    low = sig.lower()
    hits = [k for k in keywords if k in low]
    body_l = "\n".join(body).lower()
    for k in keywords:
        if k in body_l and k not in hits:
            hits.append(k)
    return hits


def find_insert_pos(block):
    """方法体内第一条真实指令前的插入位置(块内相对索引)。"""
    for idx, ln in enumerate(block):
        s = ln.strip()
        if not s:
            continue
        if s.startswith("."):
            continue
        if ":" in s and s.endswith(":"):   # 标签
            continue
        return idx
    return max(1, len(block) - 1)


def bump_registers(block, need=1):
    """寄存器不足时提升 .locals / .registers，返回新块。"""
    for idx, ln in enumerate(block):
        m = LOCALS_RE.match(ln)
        if m:
            cur = int(m.group(2))
            if cur < need:
                block[idx] = "    .%s %d" % (m.group(1), need)
            return block, True
    return block, False


def make_patch(ret_type, args):
    if ret_type == "Z":
        val = "0x1" if args.ret == "true" else "0x0"
        return ["    const/4 v0, %s" % val, "    return v0"]
    if ret_type in ("I", "J", "S", "B", "C"):
        if ret_type != "I":
            return None
        return ["    const/4 v0, 0x%x" % args.int_value, "    return v0"]
    return None


def main():
    ap = argparse.ArgumentParser(description="smali 卡密判定点定位与补丁")
    ap.add_argument("target", help="smali 目录或单个 .smali 文件")
    ap.add_argument("--keywords", help="逗号分隔关键词，默认内置卡密词表")
    ap.add_argument("--apply", action="store_true", help="写回补丁(默认 dry-run)")
    ap.add_argument("--ret", choices=["true", "false"], default="true",
                    help="布尔返回值强制结果，默认 true")
    ap.add_argument("--int-value", type=int, default=0, help="int 返回值，默认 0")
    ap.add_argument("--mode", choices=["replace", "prepend"], default="replace",
                    help="replace=整个方法体替换为恒返回(默认，推荐，无死代码)；"
                         "prepend=仅在方法头插入恒返回(保留原代码，可能产生死代码与寄存器类型冲突)")
    ap.add_argument("--limit", type=int, default=0, help="最多 patch 多少个方法(0=不限)")
    ap.add_argument("--top", type=int, default=30, help="dry-run 显示条数")
    args = ap.parse_args()

    keywords = [k.strip().lower() for k in args.keywords.split(",")] \
        if args.keywords else DEFAULT_KEYWORDS

    files = []
    if os.path.isfile(args.target):
        files = [args.target]
    else:
        for dp, dns, fns in os.walk(args.target):
            dns[:] = [d for d in dns if not d.startswith(".")]
            for fn in fns:
                if fn.endswith(".smali"):
                    files.append(os.path.join(dp, fn))

    if not files:
        print("[-] no .smali found under %s" % args.target)
        return 2

    candidates = []
    for fp in files:
        try:
            for cls, sig, rt, start, end, block in parse_smali(fp):
                if sig.startswith("abstract") or " abstract " in sig:
                    continue
                hits = hit_keywords(sig, block[1:-1], keywords)
                if not hits:
                    continue
                candidates.append({"file": fp, "cls": cls, "sig": sig,
                                   "ret": rt, "start": start, "end": end,
                                   "block": block, "hits": hits})
        except Exception as e:
            print("[-] parse failed %s: %s" % (fp, e))

    candidates.sort(key=lambda c: (c["ret"] != "Z", -len(c["hits"])))
    print("[+] smali files : %d" % len(files))
    print("[+] candidates  : %d\n" % len(candidates))

    if not args.apply:
        print("== 候选判定点 (按 布尔返回值 + 命中数 排序) ==")
        for c in candidates[: args.top]:
            patch = make_patch(c["ret"], args)
            tag = "PATCHABLE" if patch else "manual   "
            print("  [%s] %s" % (tag, os.path.relpath(c["file"], args.target)
                                 if os.path.isdir(args.target) else c["file"]))
            print("        sig : %s" % c["sig"][:110])
            print("        ret : %s   hits: %s" % (c["ret"], ",".join(c["hits"][:6])))
            print("        line: %d-%d" % (c["start"] + 1, c["end"] + 1))
            print("        ins : %s" % (" / ".join(x.strip() for x in patch)
                                        if patch else "需人工改调用点或比较指令"))
        if len(candidates) > args.top:
            print("  ... %d more" % (len(candidates) - args.top))
        print("\n[dry-run] 加 --apply 才写文件。")
        return 0

    # ---- apply ----
    applied = 0
    by_file = {}
    for c in candidates:
        patch = make_patch(c["ret"], args)
        if not patch:
            continue
        if args.limit and applied >= args.limit:
            break
        by_file.setdefault(c["file"], []).append((c, patch))
        applied += 1

    for fp, items in by_file.items():
        if not os.path.exists(fp + ".bak"):
            shutil.copy2(fp, fp + ".bak")
        with open(fp, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.read().splitlines()
        # 从后往前改，避免行号偏移
        for c, patch in sorted(items, key=lambda x: -x[0]["start"]):
            if args.mode == "replace":
                # 整个方法体替换：只留 .method 签名 + .locals 1 + 恒返回 + .end method
                # 不留原指令，避免死代码引发的寄存器类型冲突(Dalvik 校验失败)
                block = [lines[c["start"]], "    .locals 1"] + patch + [".end method"]
            else:
                block = lines[c["start"]: c["end"] + 1]
                block, _ = bump_registers(block, need=1)
                pos = find_insert_pos(block)
                block[pos:pos] = patch
            lines[c["start"]: c["end"] + 1] = block
        with open(fp, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(lines) + "\n")
        print("[+] patched %s (%d methods, backup: %s.bak)" % (fp, len(items), fp))

    print("\n[+] applied %d methods" % applied)
    print("[*] 下一步: apktool b <dir> -o out.apk && 签名 && 安装验证")
    return 0


if __name__ == "__main__":
    sys.exit(main())
