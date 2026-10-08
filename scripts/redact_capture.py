#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
抓包/日志脱敏（分享前必跑）
============================
把 HAR / 日志 / 请求文本里的常见敏感字段替换为占位符，并打印「替换了什么、几条」。
用途：把材料放进 case 目录或对外分享前脱敏（对齐 references/evidence-case-conventions.md）。

用法：
  python redact_capture.py raw.har redacted.har            # 文本级脱敏（不改结构）
  python redact_capture.py raw.log - --stats               # 输出到 stdout + 打印统计
  python redact_capture.py in.txt out.txt --place '<REDACTED>'

注意：文本级替换，语义不做解析；**脱敏后请人工再扫一眼**（正则覆盖不了全部形态）。
原始文件保持不动（脱敏产物写到新文件）。
"""
import argparse
import re
import sys

RULES = [
    ("authorization", re.compile(r"(?i)(authorization\s*[:=]\s*)(?:bearer\s+)?[^\s,;\"']+")),
    ("cookie", re.compile(r"(?i)((?:set-)?cookie\s*[:=]\s*)[^\n\r\"']+")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{4,}")),
    ("api_key", re.compile(r"(?i)((?:api[_-]?key|secret|access[_-]?key|app[_-]?secret)\s*[\"']?\s*[:=]\s*[\"']?)[A-Za-z0-9_\-\.]{8,}")),
    ("password", re.compile(r"(?i)((?:passwd|password|pwd)\s*[\"']?\s*[:=]\s*[\"']?)[^\s,;&\"'}]+")),
    ("session_token", re.compile(r"(?i)((?:token|session|sessionid|sid|ticket)\s*[\"']?\s*[:=]\s*[\"']?)[A-Za-z0-9_\-\.]{8,}")),
    ("card_key_field", re.compile(r"(?i)((?:kami|card[_-]?key|cdk|license[_-]?key|activat\w*[_-]?code)\s*[\"']?\s*[:=]\s*[\"']?)[A-Za-z0-9_\-]{6,}")),
    ("phone_cn", re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")),
    ("id_card_cn", re.compile(r"(?<!\d)\d{17}[\dXx](?!\d)")),
    ("email", re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")),
    ("private_ip", re.compile(r"(?<!\d)(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}(?!\d)")),
]


def redact(text, placeholder):
    stats = {}
    for name, rx in RULES:
        def repl(m):
            if m.re.groups >= 1 and m.lastindex:
                return m.group(1) + placeholder
            return placeholder
        text, n = rx.subn(repl, text)
        if n:
            stats[name] = n
    return text, stats


def main():
    ap = argparse.ArgumentParser(description="抓包/日志文本脱敏")
    ap.add_argument("src")
    ap.add_argument("dst", help="输出文件；用 - 表示 stdout")
    ap.add_argument("--place", default="<REDACTED>")
    ap.add_argument("--stats", action="store_true", help="打印替换统计")
    args = ap.parse_args()

    with open(args.src, encoding="utf-8", errors="replace") as f:
        data = f.read()
    out, stats = redact(data, args.place)

    if args.dst == "-":
        sys.stdout.write(out)
    else:
        with open(args.dst, "w", encoding="utf-8") as f:
            f.write(out)
        print("已脱敏: %s -> %s" % (args.src, args.dst))
    total = sum(stats.values())
    print("替换 %d 处" % total + ("：" + ", ".join("%s=%d" % kv for kv in sorted(stats.items()))
                               if stats else "（未命中规则，仍建议人工复查）"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
