#!/usr/bin/env python3
"""idalib_probe.py - 用无头 IDA（idalib）在 stripped 二进制里找候选判定点。

为什么需要它：
    stripped 的 so/ELF 没有符号表，手搓 capstone 找判定点很慢。IDA 的
    字符串列表 + 交叉引用 + 反编译器正好干这个活——这就是「指定软件优先」。

做什么:
    1) idalib 打开目标并跑自动分析（auto analysis）
    2) 建字符串列表，用卡密关键词匹配（卡密/激活/授权/kami/license/expire…）
    3) 对每条命中字符串找交叉引用 → 回溯所属函数 → 按命中数排序
    4) 反编译 Top N 候选函数，伪代码落盘到 <outdir>/decomp/*.c
    5) 结果写 <outdir>/idalib.json

运行方式（必须用装好 idapro 的 uv 环境，即 ida-pro-mcp 的 venv）:
    uv run --project <ida-pro-mcp-repo> python idalib_probe.py <target> <outdir>
    # s1_recon.py 会自动拼这条命令并在 ELF/PE 分支调用

单独调试:
    uv run --project <repo> python idalib_probe.py target.so work/x --top 5
"""

import json
import os
import re
import sys
import traceback

KW = re.compile(
    r"(卡密|激活|授权|验证|会员|到期|试用|未授权|已过期|卡号|机器码|"
    r"kami|cardkey|card_key|license|licence|activate|activation|expire|trial|"
    r"not\s+authoriz|invalid\s+key|machine\s*code|serial)", re.I)


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    target, outdir = sys.argv[1], sys.argv[2]
    top = 8
    if "--top" in sys.argv:
        top = int(sys.argv[sys.argv.index("--top") + 1])
    os.makedirs(outdir, exist_ok=True)
    decdir = os.path.join(outdir, "decomp")
    os.makedirs(decdir, exist_ok=True)

    res = {"target": target, "ok": False, "kw_strings": [], "candidates": [], "decomp": []}

    import idapro
    idapro.enable_console_messages(False)
    rc = idapro.open_database(target, run_auto_analysis=True)
    if rc != 0:
        res["error"] = "open_database rc=%d（许可证/文件被占用？）" % rc
        json.dump(res, open(os.path.join(outdir, "idalib.json"), "w", encoding="utf-8"),
                  ensure_ascii=False, indent=2)
        print("[-] idalib 打开失败 rc=%d" % rc)
        return 1

    try:
        import ida_auto
        import ida_bytes
        import ida_funcs
        import ida_hexrays
        import ida_name
        import ida_strlist
        import ida_xref

        ida_auto.auto_wait()

        res["funcs"] = ida_funcs.get_func_qty()
        res["imagebase"] = hex(__import__("ida_nalt").get_imagebase())

        # 1) 字符串列表 + 关键词命中
        ida_strlist.build_strlist()
        n = ida_strlist.get_strlist_qty()
        hits = []
        for i in range(n):
            si = ida_strlist.string_info_t()
            if not ida_strlist.get_strlist_item(si, i):
                continue
            try:
                raw = ida_bytes.get_strlit_contents(si.ea, si.length, si.type)
                if not raw:
                    continue
                s = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
            except Exception:
                continue
            if KW.search(s):
                hits.append({"ea": si.ea, "s": s[:160]})
        # 1b) 字节级关键词搜索（IDA 字符串列表常漏中文串；UTF-8 直搜补齐）
        bin_search = None
        try:
            from ida_bytes import compiled_binpat_vec_t, parse_binpat_str
            try:
                from ida_bytes import bin_search, BIN_SEARCH_DOWN
            except Exception:
                from ida_search import bin_search, BIN_SEARCH_DOWN
        except Exception:
            pass
        if bin_search:
            kws = ["卡密", "激活", "授权", "验证", "会员", "到期", "试用", "未授权",
                   "kami", "cardkey", "expire", "license", "activate"]
            have = {h["ea"] for h in hits}
            INF = 0xFFFFFFFFFFFFFFFF
            for kw in kws:
                pat = " ".join("%02X" % b for b in kw.encode("utf-8"))
                pc = compiled_binpat_vec_t()
                try:
                    parse_binpat_str(pc, 0, pat, 16)
                    ea = bin_search(0, INF, pc, BIN_SEARCH_DOWN)
                except Exception:
                    continue
                cnt = 0
                while ea not in (None, INF) and cnt < 20:
                    if ea not in have:
                        have.add(ea)
                        hits.append({"ea": ea, "s": kw + "（字节级命中）"})
                    try:
                        ea = bin_search(ea + 1, INF, pc, BIN_SEARCH_DOWN)
                    except Exception:
                        break
                    cnt += 1
        res["kw_strings"] = [{"ea": hex(h["ea"]), "s": h["s"]} for h in hits]

        # 2) 字符串 xref → 所属函数（计数排序）
        fcount = {}
        for h in hits:
            xb = ida_xref.xrefblk_t()
            ok = xb.first_to(h["ea"], ida_xref.XREF_ALL)
            while ok:
                f = ida_funcs.get_func(xb.frm)
                if f:
                    key = f.start_ea
                    d = fcount.setdefault(key, {"ea": f.start_ea, "strs": set()})
                    d["strs"].add(h["s"][:80])
                ok = xb.next_to()
        ranked = sorted(fcount.values(), key=lambda d: -len(d["strs"]))
        for d in ranked[:top * 2]:
            name = ida_name.get_name(d["ea"]) or ("sub_%X" % d["ea"])
            res["candidates"].append({
                "name": name, "ea": hex(d["ea"]),
                "n_kw_strings": len(d["strs"]),
                "strings": sorted(d["strs"])[:6],
            })

        # 3) 反编译 Top N
        for c in res["candidates"][:top]:
            ea = int(c["ea"], 16)
            try:
                cf = ida_hexrays.decompile(ea)
                if cf:
                    fn = os.path.join(decdir, "%s_%s.c" % (re.sub(r"[^\w.]", "_", c["name"]), c["ea"][2:]))
                    open(fn, "w", encoding="utf-8").write(str(cf))
                    c["decomp_file"] = os.path.relpath(fn, outdir)
                    res["decomp"].append(c["decomp_file"])
            except Exception as e:
                c["decomp_error"] = str(e)[:200]

        res["ok"] = True
    except Exception:
        res["error"] = traceback.format_exc()[-1500:]
    finally:
        try:
            idapro.close_database(save=False)
        except Exception:
            pass

    json.dump(res, open(os.path.join(outdir, "idalib.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=2)
    print("[idalib] funcs=%s 关键词串=%d 候选函数=%d 已反编译=%d"
          % (res.get("funcs"), len(res.get("kw_strings", [])), len(res.get("candidates", [])),
             len(res.get("decomp", []))))
    return 0 if res.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
