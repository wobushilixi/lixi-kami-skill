#!/usr/bin/env python3
"""s4_pipeline.py - S4 一键流水线：回编 → 对齐 → 签名 → 验证（顺序固化，不会颠倒）

为什么要有它：
    实测失败里占比最大的一类不是"判定点没找对"，而是**工程顺序错**——
    漏 zipalign（装不上 -124）、对齐在签名后做（签名失效）、中文路径回编（aapt2 乱码）、
    签名只签 v1（Android 7+ 被拒）。本脚本把正确顺序固化，并在每步做硬断言。

用法:
    # 全流程（推荐）：解包目录 → 最终签名 APK
    python s4_pipeline.py all <解包目录> -o final.apk

    # 只回编（自动处理中文路径 + .bak 清理）
    python s4_pipeline.py build <解包目录> -o patched-unsigned.apk

    # 只对齐+签名+验证（已有未签名 APK）
    python s4_pipeline.py sign <unsigned.apk> -o final.apk

    # 只验证
    python s4_pipeline.py check <apk>

工具自动发现（可用参数覆盖）:
    --apktool  默认 C:\\Users\\Administrator\\tools\\apktool\\apktool.jar，其次 PATH 里的 apktool
    --zipalign 默认 C:\\qywork\\bt\\android-14\\zipalign.exe，缺失则退到纯 Python zipalign4.py
    --apksigner默认为 build-tools 的 apksigner.jar；缺失则找 uber-apk-signer.jar；再缺退 jarsigner（仅 v1，会警告）
    --ks       默认 %USERPROFILE%\\bypass.keystore；不存在则用 keytool 自动生成（密码 bypass123）

退出码: 0=全流程通过  1=某一步失败（脚本会指明是哪一步、以及原始报错尾巴）  2=用法错误
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
HOME = os.path.expanduser("~")

DEF_APKTOOL = [r"C:\Users\Administrator\tools\apktool\apktool.jar"]
DEF_ZIPALIGN = [
    r"C:\qywork\bt\android-14\zipalign.exe",
    r"C:\Users\Administrator\AppData\Local\Android\Sdk\build-tools",
]
DEF_APKSIGNER = [
    r"C:\qywork\bt\android-14\lib\apksigner.jar",
]
DEF_UBER = [
    r"C:\Users\Administrator\manyan_build\uber-apk-signer.jar",
]
KS_DEFAULT = os.path.join(HOME, "bypass.keystore")
KS_PASS = "bypass123"

results = []


def step(name, ok, detail=""):
    results.append((name, ok, detail))
    print("%s [%s] %s%s" % ("[+]" if ok else "[-]", name, "OK" if ok else "FAIL",
                            ("  " + detail) if detail else ""))
    return ok


def run(cmd, cwd=None, timeout=1800):
    print("    $ %s" % (" ".join(cmd) if isinstance(cmd, list) else cmd))
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout,
                       errors="replace")
    out = (p.stdout or "") + (p.stderr or "")
    if p.returncode != 0:
        tail = "\n".join(out.strip().splitlines()[-12:])
        print("    --- 失败输出（尾部）---\n%s\n    ----------------------" % tail)
    return p.returncode, out


def find_java():
    return shutil.which("java")


def is_ascii_path(p):
    try:
        p.encode("ascii")
        return True
    except UnicodeEncodeError:
        return False


def resolve_apktool(explicit):
    if explicit:
        return explicit if os.path.exists(explicit) else None
    for c in DEF_APKTOOL:
        if os.path.exists(c):
            return c
    return shutil.which("apktool")


def resolve_zipalign(explicit):
    if explicit:
        return explicit if os.path.exists(explicit) else None
    for c in DEF_ZIPALIGN:
        if os.path.isfile(c):
            return c
        if os.path.isdir(c):   # build-tools 目录：找最高版本子目录里的 zipalign
            subs = sorted([d for d in os.listdir(c) if os.path.isdir(os.path.join(c, d))],
                          reverse=True)
            for d in subs:
                cand = os.path.join(c, d, "zipalign.exe")
                if os.path.exists(cand):
                    return cand
    return shutil.which("zipalign")


def resolve_apksigner(explicit):
    if explicit:
        return ("jar", explicit) if os.path.exists(explicit) else None
    for c in DEF_APKSIGNER:
        if os.path.exists(c):
            return ("jar", c)
    for c in DEF_UBER:
        if os.path.exists(c):
            return ("uber", c)
    return None


def ensure_keystore(ks):
    if os.path.exists(ks):
        return True
    keytool = shutil.which("keytool")
    if not keytool:
        print("[-] 没有 keystore 且找不到 keytool；请手工生成或传 --ks")
        return False
    rc, _ = run([keytool, "-genkeypair", "-v", "-keystore", ks, "-alias", "bypass",
                 "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000",
                 "-storepass", KS_PASS, "-keypass", KS_PASS,
                 "-dname", "CN=Bypass,O=Lab,C=CN"])
    return rc == 0


def stage_build(apktool, decode_dir, out_apk, workdir=None):
    """回编。中文路径自动复制到 ASCII 工作目录；清理 .bak（apktool 会把 .bak 当未知类型报错）。"""
    build_dir = decode_dir
    tmp = None
    if not is_ascii_path(os.path.abspath(decode_dir)):
        base = workdir or tempfile.mkdtemp(prefix="s4_ascii_", dir="C:\\" if os.path.isdir("C:\\") else None)
        tmp = os.path.join(base, os.path.basename(os.path.normpath(decode_dir)))
        if os.path.exists(tmp):
            shutil.rmtree(tmp)
        print("[*] 检测到非 ASCII 路径 → 复制到 %s 回编（aapt2 中文路径会乱码）" % tmp)
        shutil.copytree(decode_dir, tmp)
        build_dir = tmp
    # 清理 .bak / .orig / .rej（apktool 会报未知类型）
    removed = 0
    for dp, _dns, fns in os.walk(build_dir):
        for fn in fns:
            if fn.endswith((".bak", ".orig", ".rej")):
                os.remove(os.path.join(dp, fn))
                removed += 1
    if removed:
        print("[*] 清理了 %d 个 .bak/.orig/.rej（否则 apktool 报未知类型）" % removed)

    java = find_java()
    if not java:
        step("build", False, "找不到 java；apktool 需要 JDK")
        return False
    cmd = [java, "-jar", apktool, "b", build_dir, "-o", out_apk]
    rc, _ = run(cmd)
    ok = rc == 0 and os.path.exists(out_apk)
    if tmp:
        shutil.rmtree(tmp, ignore_errors=True)
    return step("build 回编", ok, out_apk if ok else "apktool 报错见上方尾部输出")


def stage_align(zipalign, in_apk, out_apk):
    if zipalign:
        rc, _ = run([zipalign, "-f", "-p", "4", in_apk, out_apk])
        if rc != 0:
            return step("align 对齐", False, "官方 zipalign 失败，可试纯 Python 版")
        rc, out = run([zipalign, "-c", "-v", "4", out_apk])
        ok = rc == 0 and "Verification succesful" in out.replace("successful", "succesful")
        return step("align 对齐", ok, "官方 zipalign 自检通过" if ok else "自检未通过")
    # 退路：纯 Python（v2 修复版，含结构自检）
    zp = os.path.join(HERE, "zipalign4.py")
    rc, _ = run([sys.executable, zp, in_apk, out_apk])
    return step("align 对齐", rc == 0, "纯 Python zipalign4.py（v2）")


def stage_sign(apksigner, ks, in_apk, out_apk):
    java = find_java()
    if not java:
        return step("sign 签名", False, "找不到 java")
    kind, tool = apksigner
    if kind == "jar":
        cmd = [java, "-jar", tool, "sign",
               "--ks", ks, "--ks-pass", "pass:" + KS_PASS, "--key-pass", "pass:" + KS_PASS,
               "--ks-key-alias", "bypass",
               "--v1-signing-enabled", "true", "--v2-signing-enabled", "true",
               "--v3-signing-enabled", "true", "--out", out_apk, in_apk]
        rc, _ = run(cmd)
        ok = rc == 0 and os.path.exists(out_apk)
        if not ok:
            return step("sign 签名", False, "apksigner 报错见上")
        rc, out = run([java, "-jar", tool, "verify", "--verbose", out_apk])
        v2 = "Verified using v2 scheme (APK Signature Scheme v2): true" in out
        v3 = "Verified using v3 scheme (APK Signature Scheme v3): true" in out
        ok = rc == 0 and (v2 or v3)
        return step("sign 签名", ok, "v2=%s v3=%s" % (v2, v3))
    if kind == "uber":
        cmd = [java, "-jar", tool, "-a", in_apk, "--allowResign", "--overwrite"]
        rc, _ = run(cmd)
        # uber 输出在 in_apk 同目录，名字带 -aligned-signed
        cand = in_apk.replace(".apk", "-aligned-signed.apk")
        ok = rc == 0 and os.path.exists(cand)
        if ok and os.path.abspath(cand) != os.path.abspath(out_apk):
            shutil.copyfile(cand, out_apk)
        return step("sign 签名", ok, "uber-apk-signer（内置 zipalign + debug keystore）")
    return step("sign 签名", False, "无可用签名工具")


def stage_verify(apk):
    ok_all = True
    java = find_java()
    # 1) apksigner verify（有则用）
    signer = resolve_apksigner(None)
    if signer and signer[0] == "jar" and java:
        rc, out = run([java, "-jar", signer[1], "verify", "--verbose", apk])
        ok_all &= step("verify apksigner", rc == 0, "" if rc == 0 else "验签失败")
    # 2) 纯 Python 资产自检（对齐 + 结构 + 签名块 + dex/manifest）
    vp = os.path.join(HERE, "verify_patch.py")
    rc, out = run([sys.executable, vp, apk])
    fails = [l for l in out.splitlines() if l.startswith("[-]")]
    ok_all &= step("verify verify_patch", rc == 0, ("%d 个 FAIL" % len(fails)) if fails else "全绿")
    # 3) 对齐复检（zipalign4 v2：结构 + CRC 可读 + 4 字节）
    zp = os.path.join(HERE, "zipalign4.py")
    rc, _ = run([sys.executable, zp, "check", apk])
    ok_all &= step("verify 对齐/结构", rc == 0)
    return ok_all


def main():
    ap = argparse.ArgumentParser(add_help=True, description="S4 一键流水线：回编→对齐→签名→验证")
    ap.add_argument("mode", choices=["all", "build", "sign", "check"])
    ap.add_argument("target", help="all/build: 解包目录; sign/check: APK 路径")
    ap.add_argument("-o", "--out", default=None)
    ap.add_argument("--apktool")
    ap.add_argument("--zipalign")
    ap.add_argument("--apksigner")
    ap.add_argument("--ks", default=KS_DEFAULT)
    args = ap.parse_args()

    out = args.out or (os.path.splitext(args.target.rstrip("\\/"))[0] + "_s4.apk"
                       if args.mode in ("all", "build") else "final.apk")

    if args.mode == "check":
        ok = stage_verify(args.target)
        return 0 if ok else 1

    if args.mode == "sign":
        tmp_aligned = args.target + ".aligned.tmp.apk"
        ok = stage_align(resolve_zipalign(args.zipalign), args.target, tmp_aligned)
        if not ok:
            return 1
        if not ensure_keystore(args.ks):
            return 1
        ok = stage_sign(resolve_apksigner(args.apksigner) or ("", ""), args.ks, tmp_aligned, out)
        if ok:
            ok = stage_verify(out)
        try:
            os.remove(tmp_aligned)
        except OSError:
            pass
        return 0 if ok else 1

    # mode = all / build
    apktool = resolve_apktool(args.apktool)
    if not apktool:
        print("[-] 找不到 apktool；用 --apktool 指定路径")
        return 2
    unsigned = out if args.mode == "build" else out + ".unsigned.tmp.apk"
    ok = stage_build(apktool, args.target, unsigned)
    if not ok or args.mode == "build":
        return 0 if ok else 1

    aligned = out + ".aligned.tmp.apk"
    ok = stage_align(resolve_zipalign(args.zipalign), unsigned, aligned)
    if not ok:
        return 1
    if not ensure_keystore(args.ks):
        return 1
    ok = stage_sign(resolve_apksigner(args.apksigner) or ("", ""), args.ks, aligned, out)
    if ok:
        ok = stage_verify(out)
    for f in (unsigned, aligned):
        try:
            os.remove(f)
        except OSError:
            pass

    print("\n[=] 流水线结果：%d/%d 步通过 → %s"
          % (sum(1 for r in results if r[1]), len(results), out if ok else "未产出可用包"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
