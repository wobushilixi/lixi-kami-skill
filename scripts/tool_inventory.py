#!/usr/bin/env python3
"""tool_inventory.py - 本机逆向工具自动盘点（S0 强制第一步）。

为什么需要它：
    同一个 skill 会跑在不同机器上（本机 / 客户机 / 测试机）。「装了 IDA 却手搓 capstone /
    装了 jadx 却手动解 dex」是最常见的效率浪费。本脚本先盘出**这台机器上真正可用的工具**，
    再按「指定软件优先」原则给出该任务的反编译路线。

用法:
    python tool_inventory.py                     # 人类可读报告
    python tool_inventory.py --json work/tools.json   # 机器可读（写文件）
    python tool_inventory.py --quiet             # 只打印推荐路线

扫描范围（只读，不改任何文件）:
    - PATH 命令：ida/ida64/jadx/apktool/radare2/r2/rabin2/ghidra/adb/frida/objdump/strings/dnspy/de4dot/windbg/x64dbg 等
    - 常见安装目录：C:\\Program Files、C:\\Users\\<u>\\tools、D:\\、skill 自带路径约定
    - Python 包：capstone/unicorn/keystone/elftools/frida/androguard/lief/angr
    - Node/npx：js-reverse-mcp / chrome-devtools-mcp 可达性（只查 npm ls，不联网）
    - MCP 注册表：~/.zcode/cli/config.json 的 mcp.servers（ZCode）
    - Android 环境：emulator 目录 / adb / LDPlayer(雷电) / MuMu / BlueStacks

退出码: 0=正常 2=用法错误
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import platform

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

HOME = os.path.expanduser("~")
IS_WIN = platform.system() == "Windows"

# ---------- 工具注册表：名称 → 查找项 ----------
# kind: exe=直接可执行命令 / dir=目录含特征文件 / py=python 包 / jar=java jar / mcp=MCP 条目
TOOLS = [
    # ---- 反编译器 / 反汇编器 ----
    dict(name="IDA Pro (GUI)", kind="exe", cmds=["ida64", "ida"],
         dirs=[r"C:\Program Files\IDA Professional 9.3", r"C:\Program Files\IDA Pro 9.3",
               r"C:\Program Files\IDA Professional 9.2", r"C:\Program Files\IDA Professional 9.1",
               r"C:\Program Files\IDA Professional 9.0", r"C:\Program Files\IDA 9.3"],
         files=["ida.exe", "ida64.exe"], group="反编译器", priority=1),
    dict(name="idalib（无头 IDA，可被 MCP 调用）", kind="file",
         files=[r"C:\Program Files\IDA Professional 9.3\idalib.dll"],
         group="反编译器", priority=0),
    dict(name="JEB Pro", kind="file",
         files=[os.path.join(HOME, "tools", "jeb", "jeb_wincon.bat")],
         dirs=[r"C:\Program Files\JEB", os.path.join(HOME, "tools", "jeb")],
         group="反编译器", priority=2),
    dict(name="jadx / jadx-gui", kind="exe", cmds=["jadx", "jadx-gui"],
         dirs=[os.path.join(HOME, "tools", "jadx"), r"C:\Users\Administrator\tools\jadx-gui"],
         files=["jadx.bat", "jadx-gui-1.5.5.exe", "jadx-gui-launch.bat"],
         group="反编译器", priority=1),
    dict(name="Ghidra", kind="dir",
         dirs=[os.path.join(HOME, "tools", "ghidra"), r"C:\ghidra", r"D:\ghidra"],
         marker="support", group="反编译器", priority=3),
    dict(name="radare2", kind="exe", cmds=["radare2", "r2", "rabin2"],
         dirs=[os.path.join(HOME, "tools", "radare2")], group="反编译器", priority=4),
    dict(name="dnSpy / dnSpyEx（.NET）", kind="exe", cmds=["dnSpy", "dnSpyEx"],
         dirs=[os.path.join(HOME, "tools", "dnSpy"), r"C:\tools\dnSpy"], group="反编译器", priority=2),
    dict(name="ILSpy / ilspycmd（.NET）", kind="exe", cmds=["ilspycmd", "ILSpy"],
         group="反编译器", priority=3),

    # ---- 动态调试 / 内存 ----
    dict(name="x64dbg", kind="exe", cmds=["x64dbg", "x32dbg"],
         dirs=[r"C:\x64dbg", os.path.join(HOME, "tools", "x64dbg"), r"D:\x64dbg"],
         group="动态调试", priority=1),
    dict(name="Cheat Engine", kind="file",
         files=[r"C:\Program Files\Cheat Engine\Cheat Engine.exe",
                os.path.join(HOME, "tools", "cheatengine", "Cheat Engine", "Cheat Engine.exe")],
         dirs=[r"C:\Program Files\Cheat Engine"], group="动态调试", priority=1),
    dict(name="WinDbg", kind="exe", cmds=["windbg", "WinDbgX"], group="动态调试", priority=2),
    dict(name="Frida CLI", kind="exe", cmds=["frida", "frida-ps", "frida-trace"],
         group="动态调试", priority=1),
    dict(name="frida (python 模块)", kind="py", modules=["frida"], group="动态调试", priority=1),

    # ---- Android ----
    dict(name="adb", kind="exe", cmds=["adb"],
         dirs=[r"D:\LDPlayer14\雷电模拟器14-v14.0.7.7-去广告绿色版\LDPlayer14"],
         files=["adb.exe"], group="Android", priority=0),
    dict(name="apktool", kind="jar",
         jars=[os.path.join(HOME, "tools", "apktool", "apktool.jar"),
               r"C:\Users\Administrator\manyan_build\apktool.jar"],
         group="Android", priority=0),
    dict(name="雷电模拟器 (LDPlayer)", kind="file",
         files=[r"D:\LDPlayer14\雷电模拟器14-v14.0.7.7-去广告绿色版\LDPlayer14\dnplayer.exe"],
         dirs=[r"D:\LDPlayer14", r"C:\LDPlayer"], group="Android", priority=0),
    dict(name="Android SDK build-tools（aapt2/zipalign/apksigner）", kind="file",
         files=[r"C:\qywork\bt\android-14\zipalign.exe",
                r"C:\Users\Administrator\AppData\Local\Android\Sdk\build-tools"],
         dirs=[r"C:\qywork\bt\android-14"], group="Android", priority=0),
    dict(name="BlackDex（脱壳 APK 工具，装到模拟器/真机用）", kind="file",
         files=[os.path.join(HOME, "tools", "apks", "BlackDex64_3.2.3.apk")],
         group="Android", priority=2),
    dict(name="MT 管理器（去签/编辑，装到安卓用）", kind="file",
         files=[os.path.join(HOME, "tools", "apks", "MT管理器_2.26.4.apk")],
         group="Android", priority=2),
    dict(name="ApkCheckPack（APK 壳检测）", kind="file",
         files=[os.path.join(HOME, "tools", "apkcheck", "ApkCheckPack.exe")],
         group="Android", priority=1),
    dict(name="scrcpy（投屏控制）", kind="exe", cmds=["scrcpy"], group="Android", priority=3),

    # ---- Python 逆向库 ----
    dict(name="capstone（反汇编）", kind="py", modules=["capstone"], group="Python 库", priority=0),
    dict(name="unicorn（CPU 仿真）", kind="py", modules=["unicorn"], group="Python 库", priority=0),
    dict(name="keystone（汇编）", kind="py", modules=["keystone"], group="Python 库", priority=0),
    dict(name="pyelftools", kind="py", modules=["elftools"], group="Python 库", priority=0),
    dict(name="lief（PE/ELF 解析）", kind="py", modules=["lief"], group="Python 库", priority=1),
    dict(name="angr（符号执行）", kind="py", modules=["angr"], group="Python 库", priority=3),
    dict(name="androguard（APK 分析）", kind="py", modules=["androguard"], group="Python 库", priority=2),

    # ---- 命令行通用 ----
    dict(name="objdump", kind="exe", cmds=["objdump"], group="命令行", priority=2),
    dict(name="readelf", kind="exe", cmds=["readelf"], group="命令行", priority=2),
    dict(name="strings", kind="exe", cmds=["strings"], group="命令行", priority=2),
    dict(name="java", kind="exe", cmds=["java"], group="命令行", priority=0),
    dict(name="node/npx", kind="exe", cmds=["node", "npx"], group="命令行", priority=0),
]


def which_any(cmds):
    for c in cmds:
        p = shutil.which(c)
        if p:
            return p
    return None


def find_file_any(files):
    for f in files:
        if os.path.exists(f):
            return f
    return None


def find_dir_any(dirs, marker=None, files=None):
    for d in dirs:
        if not os.path.isdir(d):
            continue
        if marker and not os.path.exists(os.path.join(d, marker)):
            # 继续往下一层找（如 tools/ghidra/ghidra_12.1.3_PUBLIC/support）
            for sub in os.listdir(d):
                sp = os.path.join(d, sub)
                if os.path.isdir(sp) and os.path.exists(os.path.join(sp, marker)):
                    return sp
            continue
        if files:
            for f in files:
                if os.path.exists(os.path.join(d, f)):
                    return d
            continue
        return d
    return None


def check_py_modules(mods):
    import importlib.util
    found = []
    for m in mods:
        try:
            if importlib.util.find_spec(m):
                found.append(m)
        except Exception:
            pass
    return found


def check_mcp_registry():
    """读 ZCode 的 MCP 注册表（只报名称，不读敏感字段）。"""
    cfgs = [
        os.path.join(HOME, ".zcode", "cli", "config.json"),
    ]
    names = []
    for c in cfgs:
        try:
            d = json.load(open(c, encoding="utf-8"))
            srv = (d.get("mcp") or {}).get("servers") or {}
            names.extend(sorted(srv.keys()))
        except Exception:
            pass
    return names


def check_npm_pkg(pkg):
    """检查 npm 全局/缓存里是否有某包（不联网）。仅查 npx 能否解析（离线时返回 False）。"""
    try:
        r = subprocess.run(["npm", "ls", "-g", "--depth=0", pkg], capture_output=True,
                           text=True, timeout=20)
        return pkg in (r.stdout or "")
    except Exception:
        return False


def probe():
    result = {"os": platform.platform(), "python": sys.version.split()[0], "groups": {}}
    groups = result["groups"]
    for t in TOOLS:
        g = groups.setdefault(t["group"], [])
        entry = {"name": t["name"], "found": False, "path": None, "priority": t.get("priority", 5)}
        try:
            if t["kind"] == "exe":
                p = which_any(t.get("cmds", []))
                if not p:
                    p = find_file_any(t.get("files", [])) or \
                        find_dir_any(t.get("dirs", []), files=t.get("files", []))
                if p:
                    entry.update(found=True, path=p)
            elif t["kind"] == "file":
                p = find_file_any(t.get("files", [])) or find_dir_any(t.get("dirs", []), files=t.get("files", []))
                if p:
                    entry.update(found=True, path=p)
            elif t["kind"] == "dir":
                p = find_dir_any(t.get("dirs", []), marker=t.get("marker"))
                if p:
                    entry.update(found=True, path=p)
            elif t["kind"] == "py":
                mods = check_py_modules(t.get("modules", []))
                if mods:
                    entry.update(found=True, path="python:" + ",".join(mods))
            elif t["kind"] == "jar":
                p = find_file_any(t.get("jars", []))
                if p:
                    entry.update(found=True, path=p)
        except Exception as e:
            entry["error"] = str(e)
        g.append(entry)
    result["mcp_registered"] = check_mcp_registry()
    return result


# ---------- 推荐路线 ----------
def recommend(res):
    def has(group, name_kw):
        for e in res["groups"].get(group, []):
            if name_kw.lower() in e["name"].lower() and e["found"]:
                return e
        return None

    idalib = has("反编译器", "idalib")
    ida = has("反编译器", "IDA Pro")
    jeb = has("反编译器", "JEB")
    jadx = has("反编译器", "jadx")
    ghidra = has("反编译器", "Ghidra")
    r2 = has("反编译器", "radare2")
    ce = has("动态调试", "Cheat Engine")
    frida = has("动态调试", "Frida")
    x64 = has("动态调试", "x64dbg")
    ld = has("Android", "雷电")
    adb = has("Android", "adb")
    apktool = has("Android", "apktool")
    mcp = res.get("mcp_registered", [])

    lines = []

    def pick(cands, task):
        for label, ok, hint in cands:
            if ok:
                lines.append("  %-22s → %s%s" % (task, label, ("（" + hint + "）") if hint else ""))
                return
        lines.append("  %-22s → 【无】手搓脚本/lief+capstone 兜底，或装工具" % task)

    lines.append("[native / so / ELF / PE]（指定软件优先，别手搓）")
    pick([("idalib-mcp（无头 IDA，首选）", bool(idalib), "无需开 GUI"),
          ("IDA Pro GUI", bool(ida), "ida-pro-mcp 配合"),
          ("JEB", bool(jeb), "重度混淆/ARM 强"),
          ("Ghidra headless", bool(ghidra), None),
          ("radare2", bool(r2), None)], "反编译 native")
    lines.append("[APK / DEX 反编译]")
    pick([("jadx-mcp / jadx", bool(jadx), "先起 jadx-gui 等 8650"),
          ("apktool + smali", bool(apktool), "回编必需"),
          ("JEB", bool(jeb), None)], "反编译 Java/native")
    lines.append("[动态 / 内存]")
    pick([("cheatengine-mcp", bool(ce), "内存读写/指针链"),
          ("x64dbg", bool(x64), None),
          ("Frida", bool(frida), "本机安卓端不可用时走静态")], "内存/调试")
    lines.append("[Android 环境]")
    pick([("雷电模拟器 + adb", bool(ld) and bool(adb), "ldconsole launch --index 0"),
          ("adb 单机", bool(adb), None)], "模拟器/设备")
    lines.append("[已注册 MCP] " + (", ".join(mcp) if mcp else "无"))
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="本机逆向工具盘点（S0 强制第一步）")
    ap.add_argument("--json", help="把结果写成 JSON 到指定路径")
    ap.add_argument("--quiet", action="store_true", help="只打印推荐路线")
    args = ap.parse_args()

    res = probe()

    if not args.quiet:
        print("=" * 72)
        print("本机逆向工具盘点 | %s | python %s" % (res["os"][:60], res["python"]))
        print("=" * 72)
        for gname, entries in res["groups"].items():
            print("\n## %s" % gname)
            for e in sorted(entries, key=lambda x: x["priority"]):
                mark = "[+]" if e["found"] else "[ ]"
                path = e["path"] or ""
                if len(path) > 72:
                    path = "..." + path[-69:]
                print("  %s %-46s %s" % (mark, e["name"], path))

    print("\n" + "=" * 72)
    print("推荐路线（按本机实际可用工具，指定软件优先）")
    print("=" * 72)
    print(recommend(res))

    if args.json:
        os.makedirs(os.path.dirname(os.path.abspath(args.json)), exist_ok=True)
        json.dump(res, open(args.json, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
        print("\n[已写出] %s" % args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
