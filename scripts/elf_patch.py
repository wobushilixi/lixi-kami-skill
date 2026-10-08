#!/usr/bin/env python3
"""elf_patch.py - ELF 门控（验证分支）定位与 patch，用于卡密校验写在 ELF 里的场景。

用法:
    # 1) 列出函数范围内的分支类指令（CBZ/CBNZ/B.cond/B）
    python elf_patch.py <elf> --func <symbol> [--size N]
    python elf_patch.py <elf> --addr 0x0a8cc30 --size 2004

    # 2) 把某个分支指令改成「无条件执行下一条」（等价 NOP 但保持 4 字节布局）
    python elf_patch.py <elf> --addr 0x0a8db54 --to-next --out patched.elf

    # 3) 直接 NOP 掉某条指令（4 字节 NOP）
    python elf_patch.py <elf> --addr 0x0a910e4 --nop --out patched.elf

    # 4) 只看不解写
    python elf_patch.py <elf> --addr 0x0a910dc --size 32

背景（实测经验）:
    - aarch64 验证流程常见门控: cbz wN, #fail  /  b.eq #fail
    - **不要无脑 NOP 分支**：成功后续常有 str/mov 等状态写入（写状态字、初始化会话），
      把整条分支 NOP 掉会让后续初始化不执行，表现为"卡住/功能不完整"。
      正确做法是 `b #addr+4`（强制执行下一条），失败分支被跳过，成功后续完整保留。
    - ELF PIE 且 PT_LOAD 的 offset==vaddr 时，**文件偏移 = 运行地址**；否则需做 p_offset→vaddr 映射。
    - 定位门控的实用技巧：用 capstones/ida 反汇编后，从「验证成功/失败」中文字符串
      的引用处（adrp/ldr）往回找最近的 CBZ/B.cond。
"""

import re
import struct
import sys

# aarch64 分支指令识别（不依赖 capstone，纯字节解析）
# CBZ/CBNZ 32位: sf bit31, [30:25]=011010, op bit24(0=CBZ,1=CBNZ), imm19[23:5], Rt[4:0]
# B.cond:        bits[31:24]=01010100, imm19[23:5], 0 bit4, cond[3:0]
# B (uncond):   bits[31:26]=000101, imm26[25:0]
COND_NAMES = {
    0: "eq", 1: "ne", 2: "hs", 3: "lo", 4: "mi", 5: "pl", 6: "vs", 7: "vc",
    8: "hi", 9: "ls", 10: "pl", 11: "mi", 12: "ge", 13: "lt", 14: "gt", 15: "al",
}
CBZ_32 = 0x34000000
CBZ_MASK = 0x7F000000      # 用于识别 32/64 位 CBZ 家族
CBNZ_OP = 0x01000000
BCOND_MASK = 0xFF000010
BCOND_PAT = 0x54000000
B_UNCOND_MASK = 0xFC000000
B_UNCOND_PAT = 0x14000000
NOP = 0xD503201F


def parse_elf_sections(data):
    """返回 {name: (vaddr, offset, size)}，仅解析 64 位 little-endian。"""
    if data[:4] != b"\x7fELF" or data[4] != 2:
        raise SystemExit("[-] 只支持 ELF64 LE")
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
    secs = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        name_off, stype, flags, addr, offset, size, link, info, align, entsz = \
            struct.unpack_from("<IIQQQQIIQQ", data, off)
        secs.append({"name_off": name_off, "type": stype, "addr": addr,
                     "off": offset, "size": size, "link": link, "entsz": entsz})
    strtab_off = secs[e_shstrndx]["off"]
    for s in secs:
        end = data.index(b"\x00", strtab_off + s["name_off"])
        s["name"] = data[strtab_off + s["name_off"]:end].decode("ascii", "ignore")
    return secs


def parse_elf_symbols(data, secs):
    out = {}
    for s in secs:
        if s["name"] not in (".symtab", ".dynsym"):
            continue
        strt = secs[s["link"]]
        n = s["size"] // 24
        for i in range(n):
            off = s["off"] + i * 24
            name_off, info, other, shndx, value, size = \
                struct.unpack_from("<IBBHQQ", data, off)
            if value == 0 or (info >> 4) not in (1, 2):   # 只取 FUNC / OBJECT
                continue
            end = data.index(b"\x00", strt["off"] + name_off)
            name = data[strt["off"] + name_off:end].decode("ascii", "ignore")
            out.setdefault(name, (value, size or 0))
    return out


def vaddr_to_off(secs, vaddr):
    for s in secs:
        span = max(s["size"], 1)
        if s["type"] != 8 and s["off"] and s["addr"] <= vaddr < s["addr"] + span:
            return s["off"] + (vaddr - s["addr"])
    return None


def off_to_vaddr(secs, off):
    for s in secs:
        span = max(s["size"], 1)
        if s["type"] != 8 and s["off"] and s["off"] <= off < s["off"] + span:
            return s["addr"] + (off - s["off"])
    return None


def demangle(name):
    """极简 C++ Itanium 反修饰：_ZN5cloud6loginEv -> cloud::login()"""
    if not name.startswith("_ZN"):
        return name
    i = 3
    parts = []
    while i < len(name):
        if name[i].isdigit():
            j = i
            while j < len(name) and name[j].isdigit():
                j += 1
            ln = int(name[i:j])
            parts.append(name[j:j + ln])
            i = j + ln
        elif name[i] == "E":
            break
        else:
            parts.append(name[i])
            i += 1
    return "::".join(p for p in parts if p) + "()"


def decode(insn, pc):
    """返回 (助记符, 目标地址) 或 None。"""
    op = struct.unpack("<I", insn)[0]
    if (op & 0x7F000000) == 0x35000000:      # CBZ/CBNZ 32/64
        is64 = (op >> 31) & 1
        is_nz = (op & CBNZ_OP) != 0
        imm19 = (op >> 5) & 0x7FFFF
        rt = op & 0x1F
        imm = (imm19 << 2) if imm19 < 0x40000 else ((imm19 << 2) - (1 << 21))
        tgt = pc + imm
        return ("%s%s" % ("cbnz" if is_nz else "cbz",
                          " x%d" % rt if is64 else " w%d" % rt), tgt)
    if (op & BCOND_MASK) == BCOND_PAT:
        imm19 = (op >> 5) & 0x7FFFF
        cond = op & 0xF
        imm = (imm19 << 2) if imm19 < 0x40000 else ((imm19 << 2) - (1 << 21))
        return ("b.%s" % COND_NAMES.get(cond, "?%d" % cond), pc + imm)
    if (op & B_UNCOND_MASK) == B_UNCOND_PAT:
        imm26 = op & 0x3FFFFFF
        imm = (imm26 << 2) if imm26 < 0x2000000 else ((imm26 << 2) - (1 << 27))
        return ("b", pc + imm)
    return None


def patch_to_next(old_word):
    """把分支指令改成 b #(pc+4)：跳过本条，强制执行下一条。"""
    delta = 4
    imm26 = delta >> 2
    return 0x14000000 | (imm26 & 0x3FFFFFF)


def main():
    a = sys.argv[1:]
    if len(a) < 2:
        print(__doc__)
        return 2
    path = a[0]
    with open(path, "rb") as f:
        data = bytearray(f.read())

    def arg(name, default=None):
        return a[a.index(name) + 1] if name in a else default

    addr = arg("--addr")
    func = arg("--func")
    find_str = arg("--str")
    size = int(arg("--size", "0") or 0)
    out = arg("--out")
    to_next = "--to-next" in a
    do_nop = "--nop" in a

    secs = parse_elf_sections(data)

    # --str：在可读段里搜验证相关字符串，输出地址（用于回溯门控）
    if find_str:
        keys = [find_str] if find_str != "auto" else [
            "验证成功", "验证失败", "登录成功", "登录失败", "校验失败",
            "卡密错误", "已过期", "过期", "success", "failed", "expired", "invalid",
        ]
        print("[+] 在可读段搜索字符串：%s\n" % ("、".join(keys)))
        for s in secs:
            if not (s["name"] in (".rodata", ".data", ".rdata", ".data.rel.ro", ".rodata.str1.1")
                    or "rodata" in s["name"] or "data" in s["name"]):
                continue
            blob = bytes(data[s["off"]: s["off"] + s["size"]])
            for k in keys:
                kb = k.encode("utf-8")
                start = 0
                while True:
                    i = blob.find(kb, start)
                    if i < 0:
                        break
                    vaddr = s["addr"] + i
                    print("  0x%08x  %-14s  \"%s\"" % (vaddr, s["name"], k))
                    start = i + 1
        print("\n[*] 用法：拿到字符串地址后，在 Ghidra/IDA 里查它的交叉引用(xref)，"
              "往回找最近的 CBZ / B.cond 即门控；再用 --addr <门控地址> 精确定位。")
        return 0

    syms = parse_elf_symbols(data, secs)

    if func:
        hit_name = func
        if func not in syms:
            low = func.lower()
            cands = [(k, v) for k, v in syms.items()
                     if low in k.lower() or low in demangle(k).lower()]
            if not cands:
                print("[-] 未找到符号 %s（文件可能被 strip，请改用 --addr + 反汇编定位）" % func)
                return 2
            print("[!] 未精确命中 '%s'，模糊候选 %d 个：" % (func, len(cands)))
            for k, (v, sz) in cands[:10]:
                print("    %-46s @ 0x%-9x size=%-6d %s" % (k[:46], v, sz, demangle(k)))
            print("[*] 选一个地址用 --addr <地址> 精确定位")
            return 3
        hit_name = func
        base, fsize = syms[hit_name]
        size = fsize or 0x400
        print("[+] %s  (%s) @ 0x%x size=%d" % (hit_name, demangle(hit_name), base, size))
        addr = hex(base)
    elif not addr:
        print(__doc__)
        return 2

    start = int(addr, 16)
    off = vaddr_to_off(secs, start)
    if off is None:
        print("[-] 地址 0x%x 不在任何已加载节内" % start)
        return 2

    print("[+] 扫描 0x%x .. 0x%x\n" % (start, start + size))
    changed = False
    for pc in range(start, start + size, 4):
        o = vaddr_to_off(secs, pc)
        if o is None or o + 4 > len(data):
            continue
        word = struct.unpack_from("<I", data, o)[0]
        d = decode(struct.pack("<I", word), pc)
        if not d:
            continue
        mn, tgt = d
        mark = ""
        if to_next and pc == start:
            new = patch_to_next(word)
            struct.pack_into("<I", data, o, new)
            changed = True
            mark = "  ==> patched to b #0x%x" % (pc + 4)
        elif do_nop and pc == start:
            struct.pack_into("<I", data, o, NOP)
            changed = True
            mark = "  ==> NOP"
        print("  0x%08x: %08x   %-12s -> 0x%x%s" % (pc, word, mn, tgt, mark))

    if changed and out:
        with open(out, "wb") as f:
            f.write(data)
        print("\n[+] 已写入 %s" % out)
    elif changed and not out:
        print("\n[!] 已修改内存镜像但未指定 --out，未写盘")
    else:
        print("\n[*] 只读扫描，未修改（加 --to-next 或 --nop 才会写）")

    print("[*] 提醒：NOP 掉分支会跳过其后所有指令。若失败分支后面是「写状态字/初始化」，"
          "请改用 --to-next 保留成功后续。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
