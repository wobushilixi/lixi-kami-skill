#!/usr/bin/env python3
"""zipalign4.py - 纯 Python APK 对齐（不依赖 zipalign.exe / build-tools）。

用法:
    python zipalign4.py check <apk>                    # 只检查对齐 + 可读性
    python zipalign4.py <in.apk> <out.apk>             # 对齐输出（默认 -p 4）
    python zipalign4.py --page16 <in.apk> <out.apk>    # .so 额外 16KB 页对齐(等价 zipalign -f -p 4 4)

为什么必须做这一步:
    apktool b 不会做对齐。Android 对未对齐 APK 直接判 INSTALL_FAILED_INVALID_APK(-124)，
    Android 11+ 尤其严格。实测过 94 条目 / 72 个 STORED 有 54 个未对齐 → 装不上。

原理（v2 重写，2026-10-08）:
    用 zipfile 重打包：给每个 STORED 条目的 local header 追加一个 0xD935 对齐 extra 字段，
    使「数据区起始偏移」满足对齐要求。整包由 zipfile 重新写出，中央目录偏移由标准库
    自动重算，不会出现手改字节导致的偏移失效。
    旧版 (v1) 直接手改 local header 字节、不动中央目录 → 输出 zip 损坏、条目读不出来，
    且 check 会静默放行损坏文件。已修复。

自检口径:
    check 会同时验证 ①每个 STORED 条目数据偏移对齐 ②中央目录指向的 local header 有效
    ③zip 全部条目 CRC 可读。任一不满足 = FAIL。
    换机器复核：官方 `zipalign.exe -c -v 4 out.apk` 必须输出 "Verification succesful"。
"""

import struct
import sys
import zipfile

PAGE = 4
PAGE16 = 16 * 1024

# ZIP extra field id 0xD935 是 Android 官方 zipalign 使用的数据对齐标记
ALIGN_EXTRA_ID = 0xD935


def _stored_data_offset(f, info):
    """返回 (数据偏移, header 是否有效)。header 无效时数据偏移返回 None。"""
    f.seek(info.header_offset)
    head = f.read(30)
    if len(head) < 30 or head[:4] != b"PK\x03\x04":
        return None, False
    n_len, e_len = struct.unpack_from("<HH", head, 26)
    return info.header_offset + 30 + n_len + e_len, True


def check(path, page16=False):
    """返回 (entries, stored, misaligned, bad_header, details)。

    bad_header = 中央目录指向的偏移处不是有效的 local header（zip 已损坏）。
    """
    entries = stored = mis = bad = 0
    details = []
    with open(path, "rb") as f, zipfile.ZipFile(path) as zf:
        try:
            infos = zf.infolist()
        except Exception as e:
            return 0, 0, 0, 1, ["中央目录无法解析：%s" % e]
        for info in infos:
            entries += 1
            if info.compress_type != zipfile.ZIP_STORED:
                continue
            stored += 1
            data_off, ok = _stored_data_offset(f, info)
            if not ok:
                bad += 1
                if len(details) < 20:
                    details.append("%s: 中央目录偏移 %d 处不是有效 local header → zip 已损坏"
                                   % (info.filename, info.header_offset))
                continue
            need = PAGE16 if (page16 and info.filename.endswith(".so")) else PAGE
            if data_off % need != 0:
                mis += 1
                if len(details) < 20:
                    details.append("%s @ data_off=%d (需 %d 对齐)" % (info.filename, data_off, need))
    return entries, stored, mis, bad, details


def check_readable(path):
    """全条目 CRC 可读性检查。返回 (ok, msg)。"""
    try:
        with zipfile.ZipFile(path) as zf:
            bad = zf.testzip()
            if bad:
                return False, "条目 CRC 校验失败：%s" % bad
        return True, "全部条目 CRC 可读"
    except Exception as e:
        return False, "zip 无法读取：%s" % e


def align(src, dst, page16=False):
    """重打包 zip，把 STORED 条目的数据偏移对齐（内容与压缩方式不变）。"""
    with zipfile.ZipFile(src) as zin, open(dst, "wb") as out:
        zout = zipfile.ZipFile(out, "w")
        for info in zin.infolist():
            data = zin.read(info.filename)
            zi = zipfile.ZipInfo(info.filename, info.date_time)
            zi.compress_type = info.compress_type
            zi.external_attr = info.external_attr
            zi.create_system = info.create_system
            zi.internal_attr = info.internal_attr
            extra = info.extra or b""

            if info.compress_type == zipfile.ZIP_STORED:
                need = PAGE16 if (page16 and info.filename.endswith(".so")) else PAGE
                name_len = len(info.filename.encode("utf-8"))
                pos = zout.fp.tell()                      # 本条目 local header 的写入位置
                base = pos + 30 + name_len + len(extra)   # 追加字段前的数据偏移
                pad = (-(base + 4)) % need                # +4 = 对齐 extra 字段的头
                extra = extra + struct.pack("<HH", ALIGN_EXTRA_ID, pad) + b"\x00" * pad

            zi.extra = extra
            zout.writestr(zi, data)
        zout.close()
    return len(zipfile.ZipFile(dst).infolist())


def _report(path, page16):
    e, s, m, b, det = check(path, page16)
    print("[zipalign4] entries=%d stored=%d misaligned=%d bad_header=%d" % (e, s, m, b))
    for d in det:
        print("   - %s" % d)
    return m, b


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    page16 = "--page16" in sys.argv

    if len(args) == 2 and args[0] == "check":
        m, b = _report(args[1], page16)
        ok, msg = check_readable(args[1])
        print("[zipalign4] %s：%s" % ("OK" if ok else "FAIL", msg))
        if m or b or not ok:
            if b:
                print("[-] zip 结构已损坏（条目读不出来）→ 换用官方 zipalign.exe 重新对齐，或回退上游 APK")
            if m:
                print("[-] 存在未对齐条目，直接安装会被判 INSTALL_FAILED_INVALID_APK(-124)")
            if not ok:
                print("[-] 条目不可读，禁止交付")
            return 1
        print("[+] 结构完好且全部对齐")
        return 0

    if len(args) == 2:
        e, s, m, b, det = check(args[0], page16)
        print("[zipalign4] before: entries=%d stored=%d misaligned=%d bad_header=%d" % (e, s, m, b))
        n = align(args[0], args[1], page16)
        print("[zipalign4] wrote %s (%d entries)" % (args[1], n))
        m2, b2 = _report(args[1], page16)
        ok, msg = check_readable(args[1])
        print("[zipalign4] 可读性：%s" % msg)
        if m2 or b2 or not ok:
            print("[-] 对齐后自检未通过，禁止交付（会 -124 装不上或包已损坏）")
            return 1
        print("[+] 对齐成功且结构完好，可以进入签名步骤")
        return 0

    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
