#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Parity 夹具差分（签名/算法还原的验收工具）
============================================
对比两份 JSONL 夹具，报告：行数一致性 → 逐行逐字段差异 → 首个差异定位。
替代「肉眼看 diff」；用于 references/evidence-case-conventions.md 的 parity 验收。

用法：
  python parity_diff.py tests/fixtures.jsonl out/result.jsonl
  python parity_diff.py a.jsonl b.jsonl --ignore ts,nonce,timestamp --max-show 8
  python parity_diff.py base.jsonl new.jsonl --key name      # 按 name 字段对齐行（顺序无关）

退出码：0=完全一致  1=有差异  2=参数/格式错误（可直接用于 CI / 脚本断言）
"""
import argparse
import json
import sys


def load(path, key):
    rows = []
    with open(path, encoding="utf-8") as f:
        for ln, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as e:
                raise SystemExit("[FAIL] %s 第 %d 行不是合法 JSON: %s" % (path, ln, e))
            rows.append((obj.get(key) if key else ln, obj))
    return rows


def strip(obj, ignore):
    if not ignore or not isinstance(obj, dict):
        return obj
    return {k: v for k, v in obj.items() if k not in ignore}


def diff_fields(a, b, path=""):
    """返回字段级差异列表 [(字段路径, 左值, 右值)]"""
    out = []
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            sub = path + ("." if path else "") + str(k)
            if k not in a:
                out.append((sub, "<缺失>", b[k]))
            elif k not in b:
                out.append((sub, a[k], "<缺失>"))
            else:
                out += diff_fields(a[k], b[k], sub)
    elif isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            out.append((path + ".len", len(a), len(b)))
        for i, (x, y) in enumerate(zip(a, b)):
            out += diff_fields(x, y, "%s[%d]" % (path, i))
    elif a != b:
        out.append((path or "<root>", a, b))
    return out


def brief(v, limit=60):
    s = json.dumps(v, ensure_ascii=False) if not isinstance(v, str) else v
    return s if len(s) <= limit else s[:limit] + "…"


def main():
    ap = argparse.ArgumentParser(description="JSONL parity 夹具差分")
    ap.add_argument("left")
    ap.add_argument("right")
    ap.add_argument("--key", help="按该字段对齐两侧行（顺序无关）；缺省按行号")
    ap.add_argument("--ignore", default="", help="忽略的字段名，逗号分隔（如 ts,nonce）")
    ap.add_argument("--max-show", type=int, default=10, help="最多展示多少条差异")
    args = ap.parse_args()

    ignore = {x.strip() for x in args.ignore.split(",") if x.strip()}
    left = load(args.left, args.key)
    right = load(args.right, args.key)

    print("左侧 %d 行 (%s)" % (len(left), args.left))
    print("右侧 %d 行 (%s)" % (len(right), args.right))
    if ignore:
        print("忽略字段: %s" % ", ".join(sorted(ignore)))
    print("-" * 64)

    if args.key:
        lm, rm = dict(left), dict(right)
        missing_l = [k for k in lm if k not in rm]
        missing_r = [k for k in rm if k not in lm]
        if missing_l:
            print("[!] 右侧缺少 %d 条: %s" % (len(missing_l), ", ".join(map(str, missing_l[:5]))))
        if missing_r:
            print("[!] 左侧缺少 %d 条: %s" % (len(missing_r), ", ".join(map(str, missing_r[:5]))))
        pairs = [(k, lm[k], rm[k]) for k in lm if k in rm]
    else:
        pairs = [(i + 1, a, b) for i, ((_, a), (_, b)) in enumerate(zip(left, right))]
        if len(left) != len(right):
            print("[!] 行数不一致：%d vs %d（仅比对前 %d 行）"
                  % (len(left), len(right), len(pairs)))

    diffs = 0
    for tag, a, b in pairs:
        d = diff_fields(strip(a, ignore), strip(b, ignore))
        if d:
            diffs += 1
            if diffs <= args.max_show:
                print("[差异] %s" % tag)
                for f, l, r in d[:6]:
                    print("    %-24s 左=%s" % (f, brief(l)))
                    print("    %-24s 右=%s" % ("", brief(r)))
                if len(d) > 6:
                    print("    … 该行另有 %d 处差异" % (len(d) - 6))

    print("-" * 64)
    if diffs == 0 and len(left) == len(right):
        print("parity=match  全部 %d 条一致" % len(pairs))
        return 0
    print("parity=DIFF   %d/%d 条不一致" % (diffs, len(pairs)))
    return 1


if __name__ == "__main__":
    sys.exit(main())
