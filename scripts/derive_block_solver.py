#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
自定义分块编码/加密 通用推导器（卡密/授权码算法还原用）
============================================================
融合来源：r0crawl_skills / kctf2026-题7-暗能潜流 的 METHODLOGY.md 五步推导法。
原仓库的 derive_solver.py 里 try_params() 是 NotImplementedError 空实现（只有
probe_block 单块暴力可用）；本文件是**可运行的通用推导器**，已用原题 4 组样例 +
FLAG 密文端到端实测通过：`python derive_block_solver.py --selftest`。`--selftest`
会复现 flag{T1u_2026_Kc7f_Crypt0_M4ster!}。

适用题型（等价于卡密「已知明文反推算法」）：
  - 密文是定长块（如 6 字节）的整数倍
  - 块内存在「固定骨架半字节」+ 若干「有效数据位」
  - 明文按 N 字节分块，每块做可逆位级变换（可含密钥周期）+ 块内位置重排
  - 尾块（len % N）有效位位置与完整块不同，必须单独推导
  - 手上有 ≥2 组 已知明文 ↔ 密文（有效卡密 + 它生成的机器码/密文）

为什么优先用它：只要有一枚有效样本，全部参数都是确定性可反推的——
不必猜算法、不必爆破、不必硬啃混淆代码（OLLVM/VMP 目标尤其受益）。

约定（可由搜索自动校正，不必手工假死）：
  - 块序：'r2l' = 从明文右侧分块、块序从右往左（尾块在密文最后，最常见）
          'l2r' = 密文块序与明文从左到右一致（尾块在密文最前）
  - 块内有效半字节按索引升序、两两成对（第 i 对 = 第 i 个明文字节）
  - 变换：不交换 (H,L)->(H+p, L+q)；交换 (H,L)->(L+p2, H+q2)
  - 每字节用哪种形式由「密钥序列」决定（周期 ≤ --max-period）

用法：
  python derive_block_solver.py --samples samples.json --block-size 6 --chunk 3
  python derive_block_solver.py --samples s.json --decrypt <hex> --expect 'flag{...}'
  python derive_block_solver.py --selftest
"""
import argparse
import itertools
import json
import sys


# ----------------------------------------------------------------------
# 基础
# ----------------------------------------------------------------------
def nibbles_of(block):
    out = []
    for b in block:
        out.append(b >> 4)
        out.append(b & 0xF)
    return out


def split_blocks(hexstr, block_size):
    raw = bytes.fromhex(hexstr)
    if len(raw) % block_size:
        raise ValueError("密文长度 %d 不是块大小 %d 的整数倍" % (len(raw), block_size))
    return [raw[i:i + block_size] for i in range(0, len(raw), block_size)]


def cipher_ranges(plain_len, nblocks, chunk, orient):
    """给出密文各块对应的明文字节区间 [(start,end), ...]（按密文块序）。
    'r2l': 从明文右侧每 chunk 字节分块并按该顺序输出 —— 尾块是明文最左的余数，
           因此它出现在密文最后；首块对应明文最右区间（区间是逆序的）。
    'l2r': 从左往右分块，尾块在密文最前。"""
    out = []
    if orient == "r2l":
        end = plain_len
        while end > 0:
            start = max(0, end - chunk)
            out.append((start, end))
            end = start
    else:
        pos = 0
        while pos < plain_len:
            out.append((pos, min(pos + chunk, plain_len)))
            pos += chunk
    return out if len(out) == nblocks else None


# ----------------------------------------------------------------------
# 单块尺寸的结构推导
# ----------------------------------------------------------------------
def derive_for_size(size, eq_obs, const_blocks, total_nib):
    """eq_obs: [(密文块, 明文bytes, 明文全局起始偏移)]；const_blocks: 仅用于
    校验「未选中位置恒定」的该尺寸密文块。返回候选解列表。

    变换模型（比『两套独立偏移』更本质，且避免单块伪解）：
        明文字节 (H,L) 的两个半字节各加固定偏移：L+pL、H+pH，
        二者在密文对 (a,b) 里的先后顺序由密钥序列按字节决定：
          flag=True  : (a,b) = (L+pL, H+pH)
          flag=False : (a,b) = (H+pH, L+pL)
    """
    need = 2 * size
    out = []
    for positions in itertools.combinations(range(total_nib), need):
        ok_skel = True
        for idx in range(total_nib):
            if idx in positions:
                continue
            if len({nibbles_of(b)[idx] for b in const_blocks}) != 1:
                ok_skel = False
                break
        if not ok_skel:
            continue
        for perm in itertools.permutations(range(size)):
            eqs = []
            for blk, plain, base in eq_obs:
                nib = nibbles_of(blk)
                for src in range(size):
                    a, b = nib[positions[2 * src]], nib[positions[2 * src + 1]]
                    dst = perm[src]                       # 该密文对解出的明文字节在块内位置
                    H, L = plain[dst] >> 4, plain[dst] & 0xF
                    # 两种先后顺序下的 (pL,pH) 候选
                    first_L = ((a - L) % 16, (b - H) % 16)   # flag=True
                    first_H = ((b - L) % 16, (a - H) % 16)   # flag=False
                    eqs.append((first_L, first_H, base + dst, src))
            cands = {e[0] for e in eqs} | {e[1] for e in eqs}
            for pl_ph in cands:
                flags, ok = {}, True
                for first_L, first_H, glob_idx, src in eqs:
                    hits = tuple(f for f, cand in ((True, first_L), (False, first_H)) if cand == pl_ph)
                    if not hits:
                        ok = False
                        break
                    flags[(glob_idx, src)] = hits
                if ok:
                    out.append({"size": size, "pos": positions, "perm": perm,
                                "pl": pl_ph[0], "ph": pl_ph[1], "flags": flags})
    return out


def pattern_ok(flags, max_period, mode):
    """每字节用哪种变换形式，能否由周期 ≤ max_period 的密钥序列解释。
    返回 (P, {slot: 可行形式}) 或 None。flags 键 = (明文全局索引, 块内索引)。"""
    for P in range(1, max_period + 1):
        slot_map, ok = {}, True
        for (glob_idx, src), choices in flags.items():
            slot = (glob_idx if mode == "global" else src) % P
            if slot not in slot_map:
                slot_map[slot] = choices
            else:
                keep = tuple(c for c in choices if c in slot_map[slot])
                if not keep:
                    ok = False
                    break
                slot_map[slot] = keep
        if ok:
            return P, slot_map
    return None


def merge_slot_maps(maps):
    merged = {}
    for m in maps:
        for slot, choices in m.items():
            if slot in merged:
                both = tuple(c for c in choices if c in merged[slot])
                if not both:
                    return None
                merged[slot] = both
            else:
                merged[slot] = choices
    return merged


# ----------------------------------------------------------------------
# 解码
# ----------------------------------------------------------------------
def slot_len(conf):
    return (max(conf["pattern_map"].keys()) + 1) if conf["pattern_map"] else 1


def decode_block(blk, r, conf, base):
    info = conf["sizes"][r]
    pos, perm = info["pos"], info["perm"]
    nib = nibbles_of(blk)
    P = slot_len(conf)
    out = [0] * r
    for src in range(r):
        a, b = nib[pos[2 * src]], nib[pos[2 * src + 1]]
        glob_idx = base + perm[src]
        slot = (glob_idx if conf["mode"] == "global" else src) % P
        choices = conf["pattern_map"].get(slot) or info["flags"].get((glob_idx, src), (False,))
        if choices[0]:                                   # 密文对顺序：(L+pL, H+pH)
            L, H = (a - conf["pl"]) % 16, (b - conf["ph"]) % 16
        else:                                            # 密文对顺序：(H+pH, L+pL)
            H, L = (a - conf["ph"]) % 16, (b - conf["pl"]) % 16
        out[perm[src]] = (H << 4) | L
    return out


def decode_with_ranges(blocks, ranges, conf):
    starts = [s for s, _ in ranges]
    if min(starts) != 0:
        return None
    total = max(e for _, e in ranges)
    out = bytearray(total)
    for blk, (start, end) in zip(blocks, ranges):
        r = end - start
        if r not in conf["sizes"]:
            return None
        out[start:end] = bytes(decode_block(blk, r, conf, start))
    return bytes(out)


def decode_samples(samples, block_size, chunk, conf):
    dec = {}
    for s in samples:
        plain = s["plain"].encode("latin1") if isinstance(s["plain"], str) else s["plain"]
        blocks = split_blocks(s["cipher"], block_size)
        ranges = cipher_ranges(len(plain), len(blocks), chunk, conf["orient"])
        if ranges is None:
            return None
        got = decode_with_ranges(blocks, ranges, conf)
        if got != plain:
            return None
        dec[s["cipher"]] = got
    return dec


def printable_ratio(bs):
    t = bs.decode("latin1")
    return sum(1 for ch in t if 32 <= ord(ch) < 127) / max(1, len(t))


def decrypt(cipher_hex, plain_len, conf, block_size, chunk):
    blocks = split_blocks(cipher_hex, block_size)
    totals = [plain_len] if plain_len else list(range(len(blocks), len(blocks) * chunk + 1))
    best = None
    for total in totals:
        ranges = cipher_ranges(total, len(blocks), chunk, conf["orient"])
        if ranges is None:
            continue
        got = decode_with_ranges(blocks, ranges, conf)
        if got is None:
            continue
        score = printable_ratio(got)
        if best is None or score > best[0]:
            best = (score, got)
    return best[1] if best else None


# ----------------------------------------------------------------------
# 主搜索
# ----------------------------------------------------------------------
def solve(samples, extra_ciphers, block_size, chunk, max_period):
    solutions = []
    for orient in ("r2l", "l2r"):
        eq_by_size, const_by_size = {}, {}
        ok = True
        for s in samples:
            plain = s["plain"].encode("latin1") if isinstance(s["plain"], str) else s["plain"]
            blocks = split_blocks(s["cipher"], block_size)
            ranges = cipher_ranges(len(plain), len(blocks), chunk, orient)
            if ranges is None:
                ok = False
                break
            for blk, (start, end) in zip(blocks, ranges):
                r = end - start
                eq_by_size.setdefault(r, []).append((blk, plain[start:end], start))
                const_by_size.setdefault(r, []).append(blk)
        if not ok:
            continue
        # 待解密密文的「非末块」可作完整块的恒定观测（末块长度未知，不参与）
        for c in extra_ciphers:
            cb = split_blocks(c, block_size)
            if len(cb) > 1:
                const_by_size.setdefault(chunk, []).extend(cb[:-1])

        per_size, ok = [], True
        for size, obs in sorted(eq_by_size.items()):
            cands = derive_for_size(size, obs, const_by_size.get(size, []), block_size * 2)
            if not cands:
                ok = False
                break
            per_size.append(cands)
        if not ok:
            continue

        for combo in itertools.product(*per_size):
            pl, ph = combo[0]["pl"], combo[0]["ph"]
            if any(c["pl"] != pl or c["ph"] != ph for c in combo):
                continue
            for mode in ("global", "block"):
                maps, good = [], True
                for c in combo:
                    pat = pattern_ok(c["flags"], max_period, mode)
                    if not pat:
                        good = False
                        break
                    maps.append(pat[1])
                if not good:
                    continue
                merged = merge_slot_maps(maps)
                if merged is None:
                    continue
                conf = {"orient": orient, "pl": pl, "ph": ph, "mode": mode,
                        "sizes": {c["size"]: c for c in combo}, "pattern_map": merged}
                dec = decode_samples(samples, block_size, chunk, conf)
                if dec is None:
                    continue
                extra_dec = decrypt(extra_ciphers[0], None, conf, block_size, chunk) if extra_ciphers else None
                score = (max(merged) + 1,
                         0 if (extra_dec is not None and printable_ratio(extra_dec) > 0.9) else 1)
                solutions.append((score, conf, merged, dec, extra_dec))
    solutions.sort(key=lambda x: x[0])
    return solutions


# ----------------------------------------------------------------------
# 报告
# ----------------------------------------------------------------------
def report(conf, merged, samples, dec, extra_dec):
    print("=" * 72)
    print("推导成功，参数如下（可直接写成解密器）：")
    for r in sorted(conf["sizes"]):
        c = conf["sizes"][r]
        print("  %d 字节块: 有效位(半字节索引)=%-18s 重排(密文序->明文序)=%s"
              % (r, list(c["pos"]), list(c["perm"])))
    print("  变换: L+%d、H+%d（各 mod 16）；两者在密文对中的先后顺序由密钥序列决定"
          % (conf["pl"], conf["ph"]))
    print("  密钥序列: 周期=%d 槽位(0=不交换/1=交换)=%s  索引方式=%s"
          % (slot_len(conf), {k: v[0] for k, v in sorted(merged.items())}, conf["mode"]))
    print("  块序: %s" % ("从右往左（尾块在密文最后）" if conf["orient"] == "r2l"
                          else "从左往右（尾块在密文最前）"))
    print("-" * 72)
    for s in samples:
        print("  样例 %-8r -> %s   ✓" % (s["plain"], dec[s["cipher"]].decode("latin1")))
    if extra_dec:
        print("  目标密文 -> %s" % extra_dec.decode("latin1"))


# ----------------------------------------------------------------------
# 自检：KCTF2026 第 7 题「暗能潜流 / HexMaze」
# ----------------------------------------------------------------------
SELFTEST_SAMPLES = [
    {"plain": "TLU", "cipher": "94AA48550495"},
    {"plain": "Hello", "cipher": "34BB405504B5223594B94C53"},
    {"plain": "2026", "cipher": "A48844556485223322356483"},
    {"plain": "abcd!", "cipher": "547B475584B5223564BB4553"},
]
SELFTEST_FLAG_CT = ("14CC4655547594BC475584C5848A43551495448C445584C5D4C9475564C534A84B55"
                    "A4B574BA4355F495A48844556485648C495534A5548C4F5584A5B4BB405554B522332235A4B3")
SELFTEST_EXPECT = "flag{T1u_2026_Kc7f_Crypt0_M4ster!}"


def selftest():
    sols = solve(SELFTEST_SAMPLES, [SELFTEST_FLAG_CT], 6, 3, max_period=4)
    if not sols:
        print("[FAIL] 未能推导出任何参数")
        return 1
    score, conf, merged, dec, extra_dec = sols[0]
    report(conf, merged, SELFTEST_SAMPLES, dec, extra_dec)
    txt = extra_dec.decode("latin1") if extra_dec else "<解密失败>"
    print("-" * 72)
    print("  期望: %s" % SELFTEST_EXPECT)
    print("  自检: %s（共 %d 组自洽解）" % ("PASS" if txt == SELFTEST_EXPECT else "FAIL", len(sols)))
    return 0 if txt == SELFTEST_EXPECT else 1


def main():
    ap = argparse.ArgumentParser(description="自定义分块编码通用推导器（已知明文反推参数）")
    ap.add_argument("--samples", help='样例 JSON: [{"plain":..,"cipher":hex},..]')
    ap.add_argument("--block-size", type=int, default=6)
    ap.add_argument("--chunk", type=int, default=3)
    ap.add_argument("--max-period", type=int, default=4)
    ap.add_argument("--decrypt", help="用推得参数解这条密文 (hex)")
    ap.add_argument("--plain-len", type=int, default=0, help="待解明文长度（可选，加速）")
    ap.add_argument("--expect", help="与 --decrypt 结果比对")
    ap.add_argument("--selftest", action="store_true", help="跑内置 KCTF 第 7 题自检")
    args = ap.parse_args()

    if args.selftest:
        sys.exit(selftest())
    if not args.samples:
        ap.error("需要 --samples 或 --selftest")
    samples = json.load(open(args.samples, encoding="utf-8"))
    extra = [args.decrypt] if args.decrypt else []
    sols = solve(samples, extra, args.block_size, args.chunk, args.max_period)
    if not sols:
        print("[FAIL] 搜索空间内没有能自洽解全部样例的参数。")
        print("       先核对 --block-size / --chunk；若目标是标准密码学算法")
        print("       （AES/RSA/RC4，无固定骨架、无已知明文块结构），本工具不适用。")
        sys.exit(2)
    print("共 %d 组自洽解，按最短密钥周期排序：\n" % len(sols))
    for i, (score, conf, merged, dec, extra_dec) in enumerate(sols[:5]):
        print("--- 解 #%d ---" % (i + 1))
        report(conf, merged, samples, dec, extra_dec)
        print()
    if args.expect:
        got = sols[0][4]
        txt = got.decode("latin1") if got else "<解密失败>"
        print("期望: %s\n结果: %s" % (args.expect, "PASS" if txt == args.expect else "FAIL"))
        sys.exit(0 if txt == args.expect else 1)


if __name__ == "__main__":
    main()
