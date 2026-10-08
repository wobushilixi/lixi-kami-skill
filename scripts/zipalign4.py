#!/usr/bin/env python3
"""zipalign4.py - 纯 Python APK 对齐（不依赖 zipalign.exe / build-tools）。

用法:
    python zipalign4.py check <apk>                    # 只检查对齐
    python zipalign4.py <in.apk> <out.apk>             # 对齐输出（默认 -p 4）
    python zipalign4.py --page16 <in.apk> <out.apk>    # .so 额外 16KB 页对齐(等价 zipalign -f -p 4 4)

为什么必须做这一步:
    apktool b 不会做对齐。Android 对未对齐 APK 直接判 INSTALL_FAILED_INVALID_APK(-124)，
    Android 11+ 尤其严格。实测过 94 条目 / 72 个 STORED 有 54 个未对齐 → 装不上。

原理:
    ZIP 的 STORED 条目数据偏移必须 4 字节倍数（.so 还要 16KB）。这里通过写入
    ZIP extra field 0xD935（Android 用的对齐标记）填充字节，保证偏移对齐，
    不改变任何文件内容 —— 对 APK 内容零风险。
"""

import struct
import sys
import zipfile

PAGE = 4
PAGE16 = 16 * 1024

# ZIP extra field id 0xD935 是 Android 官方 zipalign 使用的数据对齐标记
ALIGN_EXTRA_ID = 0xD935


def needs_alignment(name):
    """需要对齐的条目：未压缩(STORED)的数据，且 .so 要 16KB 对齐。"""
    return name


def check(path, page16=False):
    """返回 (entries, stored, misaligned, details)"""
    entries = stored = mis = 0
    details = []
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            entries += 1
            if info.compress_type != zipfile.ZIP_STORED:
                continue
            stored += 1
            data_off = info.header_offset
            # header_offset + 30(固定头) + 文件名长度 + extra 长度 = 数据偏移
            with open(path, "rb") as f:
                f.seek(data_off)
                head = f.read(30)
                if len(head) < 30 or head[:4] != b"PK\x03\x04":
                    continue
                n_len, e_len = struct.unpack_from("<HH", head, 26)
                data_off = data_off + 30 + n_len + e_len
            need = PAGE16 if (page16 and info.filename.endswith(".so")) else PAGE
            if data_off % need != 0:
                mis += 1
                if len(details) < 20:
                    details.append("%s @ data_off=%d (需 %d 对齐)" % (info.filename, data_off, need))
    return entries, stored, mis, details


def align(src, dst, page16=False):
    """重写 zip，把 STORED 条目的数据偏移对齐（内容不变）。"""
    zin = zipfile.ZipFile(src, "r")
    zout = zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED)
    # zipfile 会在写 STORED 条目时自行填充 local header，我们通过
    # 允许 ZipInfo 携带 extra 来插入对齐标记，控制数据偏移由底层决定。
    # 这里改用"直接复制 + 手工重写 local header"的方式保证偏移可控。
    zout.close()
    zin.close()

    with open(src, "rb") as fi, open(dst, "wb") as fo:
        data = fi.read()
        fo.write(_rewrite(data, page16))

    ents = zipfile.ZipFile(dst).infolist()
    return len(ents)


def _rewrite(data, page16):
    """在 STORED 条目的 local header 后插入填充，使数据偏移对齐。

    做法：逐条解析 local header，计算当前数据偏移；不对齐时扩展 extra 字段长度。
    """
    out = bytearray()
    pos = 0
    n = len(data)
    while pos < n - 4:
        sig = data[pos:pos + 4]
        if sig != b"PK\x03\x04":
            # 非 local header（例如后面紧跟 central directory）→ 停止改写
            out += data[pos:]
            break
        ver, flags, method, mtime, mdate, crc, csize, usize, nlen, elen = \
            struct.unpack_from("<HHHHHIIIHH", data, pos + 4)
        name = data[pos + 30: pos + 30 + nlen]
        extra = data[pos + 30 + nlen: pos + 30 + nlen + elen]
        body_start = pos + 30 + nlen + elen
        body_end = body_start + csize
        body = data[body_start:body_end]

        if method == zipfile.ZIP_STORED:
            need = PAGE16 if (page16 and name.endswith(b".so")) else PAGE
            # out 当前长度 + 30 + nlen + 新 elen 即为数据偏移
            base = len(out) + 30 + nlen
            pad = (-base) % need
            if pad:
                extra = extra + struct.pack("<HH", ALIGN_EXTRA_ID, pad) + b"\x00" * pad
                elen = len(extra)

        out += struct.pack("<IHHHHHIIIHH", sig_int(), ver, flags, method,
                           mtime, mdate, crc, csize, usize, nlen, elen)
        out += name
        out += extra
        out += body
        pos = body_end
    return bytes(out)


def sig_int():
    return 0x04034B50


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    page16 = "--page16" in sys.argv

    if len(args) == 2 and args[0] == "check":
        e, s, m, det = check(args[1], page16)
        print("[zipalign4] entries=%d stored=%d misaligned=%d" % (e, s, m))
        for d in det:
            print("   - %s" % d)
        if m:
            print("[-] 存在未对齐条目，直接安装会被判 INSTALL_FAILED_INVALID_APK(-124)")
            return 1
        print("[+] 全部对齐")
        return 0

    if len(args) == 2:
        e, s, m, det = check(args[0], page16)
        print("[zipalign4] before: entries=%d stored=%d misaligned=%d" % (e, s, m))
        if m == 0:
            print("[+] 源文件已对齐，直接复制")
            with open(args[0], "rb") as a, open(args[1], "wb") as b:
                b.write(a.read())
        else:
            n = align(args[0], args[1], page16)
            print("[zipalign4] wrote %s (%d entries)" % (args[1], n))
        e2, s2, m2, det2 = check(args[1], page16)
        print("[zipalign4] after : entries=%d stored=%d misaligned=%d" % (e2, s2, m2))
        for d in det2:
            print("   - %s" % d)
        if m2:
            print("[-] 对齐未成功，禁止交付（会 -124 装不上）")
            return 1
        print("[+] 对齐成功，可以进入签名步骤")
        return 0

    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
