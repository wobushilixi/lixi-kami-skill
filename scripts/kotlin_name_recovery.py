#!/usr/bin/env python3
"""kotlin_name_recovery.py - 从 jadx 产物还原 R8 混淆后的 Kotlin 真实名字。

原理（来自 SimoneAvogadro/android-reverse-engineering-skill 的独门技法）：
    R8 会重命名 JVM 符号，但**不能删掉 Kotlin 元数据注解**——Kotlin 运行时需要
    @Metadata / @DebugMetadata 里的 d2 字符串数组来还原真实名字。
    混淆后的类名（如 `b`）在 d2 里仍然保留原名：类全限定名、方法名、属性名。

用途：
    - 混淆 APK 里按真实语义找类："哪个类是卡密校验""哪个是 Repository/ViewModel"
    - 给反编译结果建立 混淆名 → 真实名 映射表，供后续 grep/审计

用法:
    python kotlin_name_recovery.py <jadx输出目录> [--out mapping.tsv] [--grep <正则>]
    # jadx 输出目录 = 含 sources/ 的那层（s1_recon 的 jadx_out 即可）

    --grep 模式：在全部还原名里搜索，输出 文件:真实名（找卡密类的最快方式）
      例: --grep "card|kami|verif|vip|repository"

输出:
    mapping.tsv : 文件<TAB>真实类名<TAB>还原出的成员/类型名（分号分隔，截断 60 个）
    控制台摘要 + --grep 命中列表

局限（如实）:
    - 依赖 jadx 保留注解（默认保留；加 --no-annotations 解编译会丢）
    - 解析逻辑已用合成样本验证；**待真实 Kotlin 目标复验**（本机暂无 Kotlin 样本）
"""

import argparse
import os
import re
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# 匹配 d2 = { ... }（jadx 单行/多行都可能）
D2_RE = re.compile(r"d2\s*=\s*\{(.*?)\}\s*[,)]", re.S)
META_RE = re.compile(r"@(?:Metadata|DebugMetadata)\s*\(")
STR_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')

# 纯类型描述符 Lxxx/yyy; 或 [L...;
DESC_RE = re.compile(r"^\[?L([\w/$]+);$")

# 值得保留的名字：标识符或含语义的词
INTERESTING_RE = re.compile(
    r"(card|kami|vip|verif|auth|licen[sc]e|activ|expire|pay|order|member|"
    r"repository|viewmodel|usecase|impl|manager|helper|service|api|"
    r"token|sign|net|http|login|user)", re.I)


def clean_name(s):
    """把 d2 条目转成可读名字。"""
    m = DESC_RE.match(s)
    if m:
        return m.group(1).replace("/", ".")
    return s


def parse_file(path):
    """返回 (real_class, names) 或 (None, [])。"""
    try:
        txt = open(path, encoding="utf-8", errors="ignore").read()
    except Exception:
        return None, []
    if not META_RE.search(txt):
        return None, []
    names = []
    real_class = None
    for m in D2_RE.finditer(txt):
        body = m.group(1)
        for sm in STR_RE.finditer(body):
            raw = sm.group(1)
            c = clean_name(raw)
            if not c or len(c) < 2:
                continue
            names.append(c)
    if not names:
        return None, []
    # 第一个 L...; 条目通常是类自身的全限定名
    for m in D2_RE.finditer(txt):
        for sm in STR_RE.finditer(m.group(1)):
            dm = DESC_RE.match(sm.group(1))
            if dm:
                real_class = dm.group(1).replace("/", ".")
                break
        if real_class:
            break
    # 去重保序
    seen = set()
    uniq = []
    for n in names:
        if n not in seen:
            seen.add(n)
            uniq.append(n)
    return real_class, uniq


def main():
    ap = argparse.ArgumentParser(description="Kotlin 元数据名称还原（R8 对抗）")
    ap.add_argument("jadx_dir", help="jadx 输出目录（含 sources/）")
    ap.add_argument("--out", default=None, help="mapping.tsv 输出路径（默认写到 jadx_dir 下）")
    ap.add_argument("--grep", help="在还原名字里搜索（正则，忽略大小写）")
    args = ap.parse_args()

    root = args.jadx_dir
    if not os.path.isdir(root):
        print("[-] 目录不存在:", root)
        return 2
    src = os.path.join(root, "sources")
    scan_root = src if os.path.isdir(src) else root

    files = []
    for dp, dns, fns in os.walk(scan_root):
        for fn in fns:
            if fn.endswith((".java", ".kt")):
                files.append(os.path.join(dp, fn))

    rows = []
    grep_re = re.compile(args.grep, re.I) if args.grep else None
    hits = []

    for fp in files:
        real, names = parse_file(fp)
        if not names:
            continue
        rel = os.path.relpath(fp, scan_root)
        rows.append((rel, real or "", names))
        if grep_re:
            for n in names:
                if grep_re.search(n):
                    hits.append((rel, real or "", n))

    if args.grep:
        print("[+] 命中 %d 条（在 %d 个含 Kotlin 元数据的文件中检索）" % (len(hits), len(rows)))
        for rel, real, n in sorted(set(hits))[:80]:
            print("  %s  | %s  | %s" % (rel, real, n))
        return 0

    out = args.out or os.path.join(root, "mapping.tsv")
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        f.write("# 混淆文件\t真实类名\t还原出的名字（截断 60）\n")
        for rel, real, names in rows:
            f.write("%s\t%s\t%s\n" % (rel, real, "; ".join(names[:60])))
    print("[+] 含 Kotlin 元数据的文件: %d / 扫描 %d 个源文件" % (len(rows), len(files)))
    print("[+] 映射已写出: %s" % out)
    # 摘要：真实类名有语义的优先展示
    show = [r for r in rows if INTERESTING_RE.search(r[1] or "")]
    if show:
        print("\n[*] 语义类名（按业务词命中，优先看这些）：")
        for rel, real, names in show[:30]:
            print("  %s  ->  %s" % (rel, real))
    return 0


if __name__ == "__main__":
    sys.exit(main())
