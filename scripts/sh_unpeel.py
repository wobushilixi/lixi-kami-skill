#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sh_unpeel.py — 加密 shell 脚本通用剥壳器（lixi-nixiang-skill S1/S3）
思路来源：逆向 RX/ZF/龙茶/铭白/EON/Super/春秋 等开源 sh 加密工具总结的编码链规律。
所有此类工具 = 自解压 loader + 多层编码链载荷，不管套多少层，反复自动剥离直到出现明文脚本。

支持自动识别/剥离的层：
  hex → base64 → gzip / bzip2 / zlib(raw+Inflater) → tar/tar.gz 解包 → ROT13/tr 变换
  → Super加密(bash🔒) 16字节循环XOR → 自截取定位(tail -n +N) → 垃圾行剔除提示

用法：
  python sh_unpeel.py <加密脚本或载荷文件> [-o out.sh] [-v]
  python sh_unpeel.py <加密脚本> --show-lines      # 打印 loader 中 tail/eval 关键行帮助定位
退出码：0=剥出明文脚本  2=已到最深层(输出残料路径)  1=错误
"""
import sys, re, base64, gzip, zlib, bz2, io, os, argparse, tarfile

MARKERS = (b"bash\xf0\x9f\x94\x92",)  # Super加密 载荷起始标记（bash🔒）

def is_hex(b: bytes) -> bool:
    s = b.strip()
    return len(s) >= 16 and len(s) % 2 == 0 and re.fullmatch(rb"[0-9a-fA-F]+", s) is not None

def is_b64(b: bytes) -> bool:
    s = b"".join(b.split())
    return len(s) >= 16 and re.fullmatch(rb"[A-Za-z0-9+/=]+", s) is not None

def rot13(bs: bytes) -> bytes:
    out = bytearray()
    for c in bs:
        if 65 <= c <= 90:
            c = (c - 65 + 13) % 26 + 65
        elif 97 <= c <= 122:
            c = (c - 97 + 13) % 26 + 97
        out.append(c)
    return bytes(out)

def score(b: bytes) -> int:
    """候选层产出评分：脚本/已知 magic 高分，乱码低分。"""
    s = b.strip()
    if looks_like_script(b):
        return 5
    if s[:2] == b"\x1f\x8b" or s[:3] == b"BZh" or s[:4] == b"PK\x03\x04":
        return 4
    if s[:4] == b"ustar" or b"\x00" in s[:512] and is_hex(s):
        return 3
    if is_hex(s) or is_b64(s):
        return 2
    try:
        tarfile.open(fileobj=io.BytesIO(b), mode="r:*").getmembers()
        return 4
    except Exception:
        pass
    printable = sum(32 <= c < 127 or c in (9, 10, 13) for c in s[:512]) / max(len(s[:512]), 1)
    return 1 if printable > 0.9 else 0

def looks_like_script(b: bytes) -> bool:
    head = b[:4096].lstrip()
    if not head:
        return False
    return (head.startswith(b"#!") or b"\nfunction " in head or
            (re.search(rb"\b(if|for|while|case|echo|eval)\b", head) is not None and
             sum(32 <= c < 127 or c in (9, 10, 13) for c in head) / max(len(head), 1) > 0.85))

def try_layers(data: bytes, verbose=False):
    """对当前数据枚举所有候选下一层，按产出评分选最优。返回 (标签, 新数据) 或 None。"""
    s = data.strip()
    cands = []  # (score, label, out)
    # 1) Super加密5.0：\nbash🔒 + 32hex(key) + hex(cipher) → 16字节循环 XOR
    for m in MARKERS:
        i = data.find(m)
        if i != -1:
            tail = data[i + len(m):].strip()
            if is_hex(tail) and len(tail) >= 66:
                raw = bytes.fromhex(tail.decode())
                key, cipher = raw[:16], raw[16:]
                out = bytes(c ^ key[n % 16] for n, c in enumerate(cipher))
                cands.append((9, "Super加密: 16字节循环XOR (key=%s)" % key.hex(), out))
    # 2) 自截取：tail -n +N
    for mm in re.finditer(rb"tail -n \+(\d+)", data):
        n = int(mm.group(1))
        lines = data.split(b"\n")
        if 1 < n <= len(lines):
            out = b"\n".join(lines[n - 1:])
            if out != data:
                cands.append((score(out) + 1, f"自截取 tail -n +{n}", out))
    # 3) hex
    if is_hex(s):
        try:
            cands.append((score(bytes.fromhex(s.decode())) + 1, "hex→bin", bytes.fromhex(s.decode())))
        except ValueError:
            pass
    # 4) base64
    if is_b64(s):
        try:
            out = base64.b64decode(s, validate=True)
            cands.append((score(out) + 1, "base64→bin", out))
        except Exception:
            pass
        # 5) ROT13→base64（铭白系：tr 'N-ZA-Mn-za-m' 双 b64 夹层）
        try:
            out = base64.b64decode(rot13(s), validate=True)
            cands.append((score(out) + 1, "ROT13→base64", out))
        except Exception:
            pass
    # 6) gzip / bzip2 / zlib
    if data[:2] == b"\x1f\x8b":
        cands.append((9, "gunzip", gzip.decompress(data)))
    if data[:3] == b"BZh":
        try:
            cands.append((9, "bunzip2", bz2.decompress(data)))
        except Exception:
            pass
    if data[:2] in (b"\x78\x9c", b"\x78\x01", b"\x78\xda"):
        try:
            cands.append((9, "zlib inflate", zlib.decompress(data)))
        except Exception:
            pass
    try:
        cands.append((9, "gunzip(尝试)", gzip.decompress(data)))
    except Exception:
        pass
    # 7) tar / tar.gz 解包
    try:
        tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
        members = tf.getmembers()
        if members:
            biggest = max(members, key=lambda m: m.size)
            cands.append((8, f"tar 解包取 {biggest.name}", tf.extractfile(biggest).read()))
    except Exception:
        pass
    if not cands:
        return None
    cands.sort(key=lambda t: t[0], reverse=True)
    sc, tag, out = cands[0]
    if sc <= 1 and out == data:
        return None
    return (tag, out)

def strip_junk_lines(data: bytes, verbose=False):
    """剔除常见干扰行（纯注释/emoji 乱码威慑行），仅当剔除后仍是脚本才采用。"""
    out, removed = [], 0
    for line in data.split(b"\n"):
        t = line.strip()
        if (not t or t.startswith(b"#") or
                not all(32 <= c < 127 or c in (9, 10, 13) for c in t)):
            removed += 1
            continue
        out.append(line)
    cand = b"\n".join(out)
    if verbose and removed:
        print(f"  [i] 剔除 {removed} 行垃圾/注释行", file=sys.stderr)
    return cand if b"eval" in cand or b"#!/" in cand or looks_like_script(cand) else data

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input")
    ap.add_argument("-o", "--output", default=None)
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--show-lines", action="store_true",
                    help="打印 loader 关键行（tail/eval/eval 链）辅助人工分析")
    a = ap.parse_args()

    data = open(a.input, "rb").read()
    if a.show_lines:
        for n, line in enumerate(data.split(b"\n"), 1):
            if re.search(rb"tail -n \+|eval |base64 -d|xxd -r|gunzip|openssl|tr -d|tar -x", line):
                print(f"{n:4d}: {line[:220]!r}")
        return 0

    trail = []
    for depth in range(1, 33):
        # 注意：loader 桩本身可能带 #! 头（如 Super加密），带加密标记时不算明文脚本
        if looks_like_script(data) and not any(m in data for m in MARKERS):
            print(f"[OK] 第 {depth - 1} 层后得到明文脚本", file=sys.stderr)
            break
        r = try_layers(data, a.verbose)
        if r is None:
            data = strip_junk_lines(data, a.verbose)
            r = try_layers(data, a.verbose)
        if r is None:
            print(f"[--] 第 {depth - 1} 层后无已知层可剥，残料已保存", file=sys.stderr)
            break
        tag, data = r
        trail.append(tag)
        print(f"  layer {depth:02d}: {tag}  → {len(data)} bytes", file=sys.stderr)
    else:
        print("[OK] 达到层数上限", file=sys.stderr)

    out = a.output or (a.input + ".unpeeled.sh")
    with open(out, "wb") as f:
        f.write(data)
    print(f"[=] 剥层记录: {' → '.join(trail) if trail else '(无)'}")
    print(f"[=] 输出: {out}")
    if looks_like_script(data):
        print("[结论] 已剥出明文脚本；若含 eval 链，用 --show-lines 查看 loader 关键行")
        return 0
    print("[结论] 未到明文：残料可能是 编码链尾部/自定义变换/加密体。"
          "下一步：--show-lines 读 loader 逻辑，或走运行时截获（见 references/sh-encrypt-reverse.md）")
    return 2

if __name__ == "__main__":
    sys.exit(main())
