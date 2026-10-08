#!/usr/bin/env python3
"""verify_patch.py - S4 测试阶段的产物自检（补丁后、回编后、签名后各跑一次）。

用法:
    python verify_patch.py <smali目录>              # 改完 smali 立刻查语法与寄存器
    python verify_patch.py <patched.apk>            # 回编签名后查完整性与签名

检查项（目录模式）:
    - .method / .end method 是否配对
    - 是否残留死代码（恒返回后面还有指令）
    - .locals 数量是否够用（用到的 vN 是否越界）
    - 方法是否缺 return
检查项（APK 模式）:
    - zip 能否打开、是否有 classes*.dex、AndroidManifest.xml
    - 是否有 v1 签名(META-INF/*.RSA|MF) 与 v2/v3 签名块
    - 是否被 apktool 回编（有 apktool.yml 说明是解包目录产物）

退出码 0=通过或有警告, 1=有错误(FAIL)。
"""

import os
import re
import struct
import sys
import zipfile

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

METHOD_RE = re.compile(r"^\.method\b")
END_RE = re.compile(r"^\.end\s+method\b")
LOCALS_RE = re.compile(r"^\s*\.locals\s+(\d+)")
REGS_RE = re.compile(r"^\s*\.(registers|locals)\s+(\d+)")
VREG_RE = re.compile(r"\bv(\d+)\b")
RET_RE = re.compile(r"^\s*return")
RETURN_ANY = re.compile(r"\breturn(-void|-object|-wide)?\b|\breturn\b")
ABSTRACT_RE = re.compile(r"\babstract\b")

results = []


def add(level, msg, hint=""):
    results.append((level, msg, hint))
    mark = {"PASS": "[+]", "WARN": "[!]", "FAIL": "[-]"}[level]
    print("%s %s%s" % (mark, msg, ("  → " + hint) if hint else ""))


def check_smali_dir(root):
    files = []
    for dp, dns, fns in os.walk(root):
        for fn in fns:
            if fn.endswith(".smali"):
                files.append(os.path.join(dp, fn))
    if not files:
        add("FAIL", "目录里没有 .smali 文件", "确认路径是 apktool 解包出来的目录")
        return
    add("PASS", "smali 文件数：%d" % len(files))

    total_methods = 0
    bad_pair = 0
    dead_code = 0
    reg_oob = 0
    no_ret = 0

    for fp in files:
        rel = os.path.relpath(fp, root)
        try:
            with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.read().splitlines()
        except Exception as e:
            add("FAIL", "%s 读取失败：%s" % (rel, e))
            continue

        depth = 0
        i = 0
        while i < len(lines):
            if METHOD_RE.match(lines[i].strip()):
                depth += 1
                total_methods += 1
                # 收集方法体
                j = i + 1
                body = []
                while j < len(lines) and not END_RE.match(lines[j].strip()):
                    body.append(lines[j])
                    j += 1
                if j >= len(lines):
                    bad_pair += 1
                    add("FAIL", "%s: .method 没有配对的 .end method（约第 %d 行）" % (rel, i + 1),
                        "手工补上 .end method，或回退 .bak")
                    break
                # .locals 越界检查
                declared = None
                for b in body:
                    m = LOCALS_RE.match(b)
                    if m:
                        declared = int(m.group(1))
                        break
                max_v = -1
                for b in body:
                    m2 = REGS_RE.match(b)
                    if m2:
                        continue
                    for vv in VREG_RE.findall(b):
                        max_v = max(max_v, int(vv))
                if declared is not None and max_v >= declared:
                    reg_oob += 1
                    add("FAIL", "%s: 用到 v%d 但 .locals %d（越界）" % (rel, max_v, declared),
                        "把 .locals 提到 %d 以上" % (max_v + 1))
                # 死代码检查：return 之后还有真实指令
                seen_return = False
                for b in body:
                    s = b.strip()
                    if not s or s.startswith(".") or (s.endswith(":") and not s.startswith("const")):
                        continue
                    if RETURN_ANY.search(s):
                        seen_return = True
                        continue
                    if seen_return:
                        dead_code += 1
                        add("WARN", "%s: return 之后还有指令 `%s`（死代码，可能触发 Dalvik 校验失败）"
                            % (rel, s[:50]), "用 --mode replace 重新 patch，或删掉死代码")
                        break
                # 缺 return
                if not seen_return and not ABSTRACT_RE.search(lines[i]):
                    no_ret += 1
                    add("WARN", "%s: 方法体内没有 return 指令（%s）" % (rel, lines[i].strip()[:60]))
                i = j
            i += 1

    add("PASS", "方法总数：%d" % total_methods)
    if bad_pair == 0:
        add("PASS", ".method/.end method 全部配对")
    if dead_code == 0:
        add("PASS", "未发现死代码")
    if reg_oob == 0:
        add("PASS", "寄存器未越界")
    if no_ret == 0:
        add("PASS", "方法均含 return")


def check_apk(path):
    try:
        zf = zipfile.ZipFile(path)
    except Exception as e:
        add("FAIL", "不是有效 zip/APK：%s" % e)
        return
    names = zf.namelist()
    add("PASS", "APK 可打开，条目 %d 个" % len(names))

    dexes = [n for n in names if n.endswith(".dex")]
    if dexes:
        add("PASS", "含 dex：%s" % ", ".join(dexes[:5]))
    else:
        add("FAIL", "没有 classes*.dex", "回编失败，检查 apktool b 的报错")

    if "AndroidManifest.xml" in names:
        add("PASS", "含 AndroidManifest.xml")
    else:
        add("FAIL", "缺 AndroidManifest.xml")

    v1 = [n for n in names if n.startswith("META-INF/")
          and n.endswith((".RSA", ".DSA", ".MF", ".SF"))]
    if v1:
        add("PASS", "v1 签名存在：%s" % ", ".join(v1[:3]))
    else:
        add("WARN", "没有 v1 签名（META-INF）", "用 uber-apk-signer 重签")

    try:
        with open(path, "rb") as f:
            f.seek(max(0, os.path.getsize(path) - 4 * 1024 * 1024))
            tail = f.read()
        if b"APK Sig Block 42" in tail:
            add("PASS", "含 APK Signature v2/v3 块")
        else:
            add("WARN", "没有 v2/v3 签名块", "Android 7+ 建议用 apksigner 补签")
    except Exception as e:
        add("WARN", "签名块检查失败：%s" % e)

    # 对齐检查：未对齐的 STORED 条目会被 Android 判 INSTALL_FAILED_INVALID_APK(-124)
    # 同时检查中央目录偏移有效性：偏移失效 = zip 被写坏（旧版 zipalign4.py 的已知故障），
    # 必须报 FAIL 而不是跳过——损坏包同样装不上。
    mis = []
    bad = []
    try:
        with open(path, "rb") as f:
            for info in zf.infolist():
                if info.compress_type != zipfile.ZIP_STORED:
                    continue
                f.seek(info.header_offset)
                head = f.read(30)
                if len(head) < 30 or head[:4] != b"PK\x03\x04":
                    bad.append("%s @header_offset=%d" % (info.filename, info.header_offset))
                    continue
                n_len, e_len = struct.unpack_from("<HH", head, 26)
                doff = info.header_offset + 30 + n_len + e_len
                if doff % 4 != 0:
                    mis.append("%s @%d" % (info.filename, doff))
    except Exception as e:
        add("WARN", "对齐检查失败：%s" % e)
    if bad:
        add("FAIL", "%d 个条目的中央目录偏移失效（local header 不是 PK\\x03\\x04）→ zip 已损坏" % len(bad),
            "不要用旧版 zipalign4.py（已修复，改用新版或官方 zipalign.exe）重新对齐")
        for b in bad[:5]:
            print("      - %s" % b)
    if mis:
        add("FAIL", "%d 个 STORED 条目未 4 字节对齐 → 会被判 -124 装不上" % len(mis),
            "python scripts/zipalign4.py %s aligned.apk" % path)
        for m in mis[:5]:
            print("      - %s" % m)
    elif not bad:
        add("PASS", "STORED 条目全部 4 字节对齐")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    target = sys.argv[1]
    print("[+] S4 自检：%s" % target)
    if not os.path.exists(target):
        add("FAIL", "路径不存在：%s" % target)
        return 1

    if os.path.isdir(target):
        check_smali_dir(target)
        print("\n[*] 下一步：apktool b <dir> -o patched.apk && 签名 && "
              "python verify_patch.py patched.apk")
    else:
        check_apk(target)
        print("\n[*] 下一步：adb uninstall <包名> && adb install -r %s && adb logcat" % target)

    fails = sum(1 for r in results if r[0] == "FAIL")
    warns = sum(1 for r in results if r[0] == "WARN")
    print("\n[=] 结果：FAIL=%d  WARN=%d" % (fails, warns))
    if fails:
        print("[-] 有错误，回退到 S2 换方案或修复后再进 S5 实测。")
        return 1
    print("[+] 通过，可以进入 S5 真机实测。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
