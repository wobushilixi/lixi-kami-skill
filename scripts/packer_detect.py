#!/usr/bin/env python3
"""packer_detect.py - 加壳 / 混淆 / 反调试 / 自校验检测（S1 分析阶段首个必跑）。

用法:
    python packer_detect.py <target> [--json out.json] [--deep]

target: APK / ZIP / DEX  /  PE(EXE/DLL)  /  ELF(SO)

输出: 壳类型 + 置信度 + 证据 + 该壳对后续动作的影响 + 建议策略。
只做只读分析，不修改样本。自动结论必须人工复核后再定方案。
"""

import argparse
import json
import math
import os
import struct
import sys
import zipfile

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


def entropy(data):
    if not data:
        return 0.0
    n = len(data)
    cnt = [0] * 256
    for b in data:
        cnt[b] += 1
    return -sum((c / n) * math.log2(c / n) for c in cnt if c)


def report(title, verdict, confidence, evidence, impact, strategy):
    print("\n" + "=" * 68)
    print("[PackerDetect] %s" % title)
    print("=" * 68)
    print("  判定     : %s   (confidence: %s)" % (verdict, confidence))
    print("  -- 证据 --")
    for e in evidence[:20]:
        print("      - %s" % e)
    if not evidence:
        print("      - (无)")
    print("  -- 对后续的影响 --")
    for i in impact:
        print("      * %s" % i)
    print("  -- 建议策略 --")
    for s in strategy:
        print("      > %s" % s)


# ------------------------------------------------------------------ PE

PE_SIGS = [
    (b"UPX!", "UPX 压缩壳"),
    (b"UPX0", "UPX 压缩壳"),
    (b"\x60\xBE\x00\x00\x00\x00\x8B", "疑似 UPX/ASPack 入口 stub"),
    (b"VMProtect", "VMProtect 虚拟机壳"),
    (b"Themida", "Themida 壳"),
    (b"WinLicense", "WinLicense 壳"),
    (b"ASPack", "ASPack 压缩壳"),
    (b"PECompact", "PECompact 压缩壳"),
    (b"NSPack", "NSPack 压缩壳"),
    (b"NsPack", "NsPack 压缩壳"),
    (b"Enigma Protector", "Enigma 壳"),
    (b"Obsidium", "Obsidium 壳"),
    (b"Armadillo", "Armadillo 壳"),
    (b"ASProtect", "ASProtect 壳"),
    (b"yoda's", "yoda's Protector"),
    (b"eXPressor", "eXPressor 壳"),
    (b".NET Reactor", ".NET Reactor 混淆"),
    (b"Confuser", "Confuser/ConfuserEx 混淆"),
    (b"SmartAssembly", "SmartAssembly 混淆"),
    (b"Eazfuscator", "Eazfuscator 混淆"),
    (b"dnGuard", "dnGuard 保护"),
]

PACKER_SECTIONS = {
    "UPX0": "UPX 压缩壳", "UPX1": "UPX 压缩壳", "UPX2": "UPX 压缩壳",
    ".UPX0": "UPX 压缩壳", ".UPX1": "UPX 压缩壳",
    ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".vmp2": "VMProtect",
    ".themida": "Themida", ".winlice": "WinLicense", ".taz": "Themida",
    ".aspack": "ASPack", ".adata": "ASPack",
    ".nsp0": "NSPack", ".nsp1": "NSPack", ".nsp2": "NSPack",
    "PEPACK": "PEPack", ".petite": "Petite",
    ".ccg": "CCG Packer", ".svkp": "SVKP",
    ".rlp": "RLPack", ".perplex": "Perplex PE-Protector",
    "nsp1": "NSPack",
}

ANTI_DBG_STRINGS = [
    b"IsDebuggerPresent", b"CheckRemoteDebuggerPresent", b"NtQueryInformationProcess",
    b"ZwSetInformationThread", b"OutputDebugString", b"FindWindow",
    b"GetTickCount", b"QueryPerformanceCounter", b"rdtsc",
    b"VirtualProtect", b"CreateToolhelp32Snapshot", b"NtSetInformationThread",
]

INTEGRITY_STRINGS = [
    b"CreateFileMapping", b"MapViewOfFile", b"ChecksumMappedFile",
    b"Imagehlp", b"psapi", b"GetModuleHandle", b"EnumProcessModules",
]


def scan_pe(path, deep=False):
    with open(path, "rb") as f:
        data = f.read()
    evidence, impacts, strategies = [], [], []
    names = []

    if data[:2] != b"MZ":
        print("[-] not a PE/APK/ELF recognizable file: %s" % path)
        return None

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        print("[-] MZ without PE header (DOS/16bit?)")
        return None

    coff = e_lfanew + 4
    machine, nsec, _, _, _, opt_size, chars = struct.unpack_from("<HHIIIHH", data, coff)
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    is64 = magic == 0x20B
    dd_off = opt + (112 if is64 else 96)
    ndd = struct.unpack_from("<I", data, opt + (108 if is64 else 92))[0]

    sec_off = opt + opt_size
    sections = []
    for i in range(nsec):
        o = sec_off + i * 40
        nm = data[o:o + 8].rstrip(b"\x00").decode("latin-1")
        vs, va, rs, rp = struct.unpack_from("<IIII", data, o + 8)
        sections.append({"name": nm, "vsize": vs, "vaddr": va, "rsize": rs, "rptr": rp})

    print("[+] PE: %s  sections=%d  machine=0x%04x" %
          ("PE32+" if is64 else "PE32", nsec, machine))
    print("[+] entropy(whole): %.3f" % entropy(data[: min(len(data), 1 << 22)]))

    # 1) 节区名判定
    for s in sections:
        hit = PACKER_SECTIONS.get(s["name"]) or PACKER_SECTIONS.get(s["name"].strip("."))
        if hit:
            names.append(hit)
            evidence.append("节区名 `%s` -> %s" % (s["name"], hit))

    # 2) 熵判定
    high = []
    for s in sections:
        if s["rsize"] == 0:
            continue
        ent = entropy(data[s["rptr"]: s["rptr"] + min(s["rsize"], 1 << 20)])
        if ent > 7.2:
            high.append("%s=%.2f" % (s["name"], ent))
    if high:
        evidence.append("高熵节区(>7.2): %s" % ", ".join(high[:6]))

    # 3) 已知壳签名
    for sig, nm in PE_SIGS:
        if sig in data:
            names.append(nm)
            evidence.append("字节签名 `%s` -> %s" % (
                sig.decode("latin-1")[:24], nm))

    # 4) 导入表规模
    imp_rva = imp_size = 0
    if ndd > 1:
        imp_rva, imp_size = struct.unpack_from("<II", data, dd_off + 8)

    def rva2off(rva):
        for s in sections:
            span = max(s["vsize"], s["rsize"])
            if s["vaddr"] <= rva < s["vaddr"] + span:
                return s["rptr"] + (rva - s["vaddr"])
        return None

    dlls = []
    if imp_rva:
        off = rva2off(imp_rva)
        if off:
            for i in range(64):
                o = off + i * 20
                if o + 20 > len(data):
                    break
                orig, _, _, name_rva, _ = struct.unpack_from("<IIIII", data, o)
                if orig == 0 and name_rva == 0:
                    break
                no = rva2off(name_rva)
                if no:
                    end = data.find(b"\x00", no)
                    dlls.append(data[no:end].decode("latin-1", "ignore"))
    print("[+] imports: %d dlls -> %s" % (len(dlls), ", ".join(dlls[:8])))
    if len(dlls) <= 3 and len(data) > 100 * 1024:
        evidence.append("导入表仅 %d 个 DLL，但文件 %d KB —— IAT 可能被壳运行时填充"
                        % (len(dlls), len(data) // 1024))
        names.append("疑似加壳(IAT 异常)")

    # 5) .NET
    is_dotnet = False
    if ndd > 14:
        cli_rva, cli_size = struct.unpack_from("<II", data, dd_off + 14 * 8)
        if cli_rva:
            is_dotnet = True
            evidence.append("存在 CLI Header (RVA=0x%x) -> .NET 程序集" % cli_rva)

    # 6) 反调试 / 自校验线索
    dbg_hits = [s.decode("latin-1") for s in ANTI_DBG_STRINGS if s in data]
    if len(dbg_hits) >= 3:
        evidence.append("反调试 API 字符串: %s" % ", ".join(dbg_hits[:8]))
    int_hits = [s.decode("latin-1") for s in INTEGRITY_STRINGS if s in data]
    if len(int_hits) >= 2:
        evidence.append("自校验 / 内存枚举线索: %s" % ", ".join(int_hits[:6]))

    # ---- 综合判定 ----
    uniq = sorted(set(n for n in names if n))
    if is_dotnet and not uniq:
        verdict, conf = ".NET 程序集（无原生壳），可能有 IL 混淆/名称混淆", "medium"
        evidence.insert(0, "未命中原生壳特征；.NET 走 dnSpy / ILSpy 直读")
        impacts = [
            "可用 dnSpy 直接出源码并右键编辑方法，改判定点最省事",
            "若命中 Confuser/.NET Reactor 等混淆，需先用 de4dot 去混淆",
            "字符串被加密时先跑一次程序或用 dnSpy 动态调试取明文",
        ]
        strategies = [
            "dnSpy 打开 → 搜卡密关键词 → 编辑方法/改 IL → 保存模块",
            "de4dot 去混淆后再 dnSpy（若类名是乱码）",
            "不脱壳也能直接改：.NET 改 IL 后重签/跳过强名称校验",
        ]
    elif uniq:
        verdict = " / ".join(uniq[:3])
        conf = "high" if any("压缩壳" in u or "虚拟机壳" in u for u in uniq) else "medium"
        impacts = [
            "直接静态反编译看到的可能是壳代码，不是真实卡密逻辑",
            "改文件可能被完整性自校验拦下（改字节 → 程序自退或报错）",
            "调试器 attach 可能被反调试检测，需先过反调试",
            "需先脱壳/绕自校验，再定位卡密判定点",
        ]
        strategies = [
            "压缩壳(UPX/ASPack)：upx -d 或调试到 OEP 后 dump + 修 IAT",
            "虚拟机壳(VMProtect/Themida)：不硬脱，改走内存补丁 / API Hook / 改客户端判定点",
            "先跑一次观察行为（联网？写注册表？），用行为反推是否值得脱壳",
            "若只改判定分支且不触发自校验，可直接在脱壳后的内存映像上 patch 再 dump",
        ]
    elif high:
        verdict, conf = "未识别壳名，但存在高熵节区（可能未知壳 / 加密资源）", "low"
        impacts = ["可能是私有壳或加密资源节，需人工确认节区内容",
                   "先确认高熵节区是资源(图片/音视频)还是代码"]
        strategies = ["dump 高熵节区单独分析熵与可反汇编性",
                      "对比同类未加壳样本的节区布局"]
    else:
        verdict, conf = "未发现明显加壳特征（原生 / 明文）", "low"
        impacts = ["可直接反汇编定位判定点",
                   "仍需确认是否有运行时自校验未体现在静态特征中"]
        strategies = ["直接 IDA / Ghidra / radare2 定位卡密判定",
                      "运行一次抓包 + API Monitor 确认是否有网络/注册表校验"]

    if dbg_hits and len(dbg_hits) >= 3:
        impacts.append("存在反调试：attach 前需先 Hook IsDebuggerPresent / NtQueryInformationProcess")
    if int_hits and len(int_hits) >= 2:
        impacts.append("存在自校验：文件级 patch 可能被检测，优先内存补丁或一并 patch 校验点")

    report("PE 分析结果", verdict, conf, evidence, impacts, strategies)
    return {"type": "PE", "dotnet": is_dotnet, "verdict": verdict,
            "confidence": conf, "evidence": evidence,
            "sections": [{"name": s["name"], "rsize": s["rsize"]} for s in sections],
            "imports": dlls}


# ----------------------------------------------------------------- APK

SHELL_SO = [
    "libjiagu", "libjiagu_x86", "libdexhelper", "libdexhelper2", "libshell",
    "libsecexe", "libsecmain", "libnqshield", "libnqos", "libexec",
    "libexecmain", "libprotect", "libx3g", "libaps", "libapssec",
    "libbaiduprotect", "libaliprotect", "libsecurity", "libtup",
    "libmobisec", "libSecShell", "libvgguard", "libddog", "libzXingSec",
    "libAppGuard", "libDexJni", "libkwscmm", "libmtguard", "libbugly",
]

# 强特征：命中即可定性为加固（桩类名 / 壳厂商包名）
STRONG_MARKERS = [
    b"StubApplication", b"ProxyApplication", b"ApplicationWrapper",
    b"com.secneo", b"com.qihoo.util", b"com.qihoo360", b"com.tencent.StubShell",
    b"com.stub.StubApp", b"com.mobisec", b"com.wrapper", b"com.ali.fixHelper",
    b"s.h.e.l.l", b"SecShell",
]
# 弱特征：普通英文词，单命中不足以定性，必须配合其它证据
WEAK_MARKERS = [
    b"jiagu", b"nqshield", b"payload", b"dexhelper",
    b"com.tencent.bugly", b"com.aliyun.security",
]


def scan_apk(path, deep=False):
    evidence, impacts, strategies = [], [], []
    names = []

    with zipfile.ZipFile(path) as zf:
        entries = zf.namelist()
        infos = {i.filename: i for i in zf.infolist()}

        dexes = [n for n in entries if n.endswith(".dex")]
        sos = [n for n in entries if n.endswith(".so")]
        assets = [n for n in entries if n.startswith("assets/")]

        total_dex = sum(infos[n].file_size for n in dexes)
        apk_size = os.path.getsize(path)

        print("[+] APK entries=%d  dex=%d (total %.1f KB)  so=%d  assets=%d"
              % (len(entries), len(dexes), total_dex / 1024.0, len(sos), len(assets)))

        # 1) 壳 so
        for n in sos:
            base = os.path.basename(n)
            for k in SHELL_SO:
                if base.startswith(k):
                    names.append("加固壳 so: %s" % base)
                    evidence.append("lib 命中壳特征: %s" % n)
                    break

        # 2) dex / manifest 中的桩标记
        blobs = []
        for n in dexes + ["AndroidManifest.xml"]:
            if n in infos and infos[n].file_size <= 40 * 1024 * 1024:
                try:
                    blobs.append((n, zf.read(n)))
                except Exception:
                    pass
        for n, blob in blobs:
            txt = blob.decode("latin-1")
            u16 = blob.decode("utf-16-le", "ignore")
            for m in STRONG_MARKERS:
                ms = m.decode("latin-1")
                if ms in txt or ms.lower() in txt.lower() or ms in u16:
                    names.append("加固桩: %s" % ms)
                    evidence.append("[强] %s 命中 `%s`" % (n, ms))
                    break
            for m in WEAK_MARKERS:
                ms = m.decode("latin-1")
                if ms in txt or ms.lower() in txt.lower() or ms in u16:
                    if not any(x.startswith("加固桩") for x in names):
                        names.append("弱特征: %s" % ms)
                        evidence.append("[弱] %s 命中 `%s`（普通词，需配合其它证据）" % (n, ms))
                    break

        # 3) 体积异常
        if total_dex < 500 * 1024 and apk_size > 5 * 1024 * 1024:
            evidence.append("dex 总大小 %.1f KB 远小于 APK %.1f MB —— 疑为壳桩，真实 dex 被加密存放"
                            % (total_dex / 1024.0, apk_size / 1024.0 / 1024.0))
            names.append("dex 体积异常（壳桩嫌疑）")

        # 4) assets 里的加密载荷
        big = [(n, infos[n].file_size) for n in assets
               if infos[n].file_size > 500 * 1024
               and os.path.splitext(n)[1].lower() in (".dat", ".bin", ".so", ".jar", ".dex", ".zip", "")]
        for n, sz in big[:5]:
            evidence.append("assets 可疑载荷: %s (%.1f KB)" % (n, sz / 1024.0))

        # 5) 签名块（决定能否直接重打包）
        sigv1 = [n for n in entries
                 if n.startswith("META-INF/") and n.endswith((".RSA", ".DSA", ".MF", ".SF"))]
        if sigv1:
            evidence.append("存在 v1 签名条目 %s —— 重打包后必须重新签名"
                            % ", ".join(sigv1[:3]))
        try:
            with open(path, "rb") as f:
                f.seek(max(0, os.path.getsize(path) - 4 * 1024 * 1024))
                tail = f.read()
            if b"APK Sig Block 42" in tail:
                evidence.append("存在 APK Signature v2/v3 块 —— 需 apksigner 重签")
        except Exception:
            pass

        # 5.5) 对抗层特征：签名校验 / 反调试 / 反注入 / 机器码绑定
        extra = []
        SIGN_CHK = ["getPackageInfo", "GET_SIGNATURES", "checkSign",
                    "PackageManager", "Signature"]
        ANTI_APK = ["isDebuggerConnected", "waitForDebugger", "TracerPid",
                    "frida", "/proc/self/maps", "27042", "/proc/net/tcp"]
        HWID = ["ANDROID_ID", "getDeviceId", "getImei", "Build.SERIAL",
                "getMacAddress", "machineCode", "hwid", "deviceid",
                "机器码", "机器号"]
        ENV_DETECT = ["com.topjohnwu.magisk", "/data/adb", "isRooted", "rooted",
                      "test-keys", "ro.debuggable", "Superuser.apk", "supersu",
                      "goldfish", "ranchu", "qemu", "isEmulator", "generic_x86",
                      "libtersafe", "libSGMainSo", "libSGSafeSo", "tp2.jar",
                      "anticheat", "gamesafe", "xposed", "lsposed"]
        for n, blob in blobs:
            txt = blob.decode("latin-1", "ignore")
            u16 = blob.decode("utf-16-le", "ignore")
            u8 = blob.decode("utf-8", "ignore")
            for label, pats, tip in (
                ("签名校验", SIGN_CHK, "重打包后会被验签拦：需 Hook 伪造签名 / 改比较分支 / 改 so，或走不重打包的 Hook 路线"),
                ("反调试/反注入", ANTI_APK, "存在反注入/反调试检测：不影响静态 patch 路线，直接改文件即可；仅在想挂调试器时才需先处理"),
                ("机器码绑定", HWID, "卡密绑设备：可 Hook 采集函数返回固定值"),
                ("环境/Root/反作弊", ENV_DETECT, "绕过卡密后仍可能被环境检测拦住（拒绝启动/限制功能）：S5 真机实测前须按 android-env-detection.md 过环境自检"),
            ):
                hits = [p for p in pats
                        if p in txt or p.lower() in txt.lower()
                        or p in u16 or p in u8]
                if len(hits) >= 2:
                    evidence.append("[对抗] %s 命中 %s -> %s"
                                    % (n, ", ".join(sorted(set(hits))[:5]), label))
                    if tip not in extra:
                        extra.append(tip)

        # 5.6) Unity 引擎识别（外挂大头，走错路线=必败，先于壳判定）
        il2cpp_so = [n for n in sos if "libil2cpp" in n]
        mono_so = [n for n in sos if "libmono" in n]
        mono_dll = [n for n in entries
                    if n.startswith("assets/bin/Data/Managed/") and n.endswith(".dll")]
        meta = [n for n in entries if n.endswith("global-metadata.dat")]
        unity_assets = [n for n in assets if "bin/Data/" in n
                        and (n.endswith(".assets") or "level" in n.lower()
                             or "sharedassets" in n)]
        unity = bool(il2cpp_so or mono_so or meta or unity_assets)
        if unity:
            names.append("__UNITY__")  # 标记，verdict 阶段单独处理
            if il2cpp_so:
                evidence.append("命中 libil2cpp.so → IL2CPP 引擎，C# 逻辑在 native，jadx 看不到")
            if mono_so or mono_dll:
                evidence.append("命中 %s → Mono 引擎，Assembly-CSharp.dll 可直接 dnSpy 反编译"
                                % (", ".join((mono_dll[:2] or mono_so[:2]))))
            if meta:
                try:
                    head = zf.read(meta[0])[:4]
                    ok = head == b"\xaf\x1b\xb1\xfa"
                    evidence.append("global-metadata.dat magic=%s (%s)"
                                    % (head.hex(),
                                       "标准未加密" if ok else "非标准 → metadata 加密，需先脱壳"))
                except Exception:
                    pass
            if unity_assets:
                evidence.append("assets/bin/Data 下 %d 个 Unity 资源文件 → Unity 实锤"
                                % len(unity_assets))

        # 6) 混淆特征（从 dex 字符串采样判断类名长度）
        if dexes and deep:
            blob = blobs[0][1] if blobs else b""
            short = blob[:1 << 20].decode("latin-1", "ignore")
            import re as _re
            cands = _re.findall(r"[a-z]{1,3}/[a-z]{1,3}/[a-z]{1,3}", short)
            if len(cands) > 30:
                evidence.append("dex 中大量 a/b/c 式短类名 —— 存在代码混淆 (%d 处)" % len(cands))
                names.append("代码混淆")

    uniq = sorted(set(names))
    is_unity = "__UNITY__" in uniq
    hard = [n for n in uniq if n.startswith("加固壳 so") or n.startswith("加固桩")]
    soft = [n for n in uniq if n.startswith("dex 体积异常")]
    obf = [n for n in uniq if "混淆" in n]
    weak = [n for n in uniq if n.startswith("弱特征")]

    # Unity 优先：引擎识别决定整条技术路线，压过壳/资源误判
    if is_unity:
        il2 = any("libil2cpp" in s for s in sos)
        if il2:
            meta_ok = any("magic=af1bb1fa" in e for e in evidence)
            if meta_ok:
                verdict = "Unity IL2CPP（metadata 未加密）—— 走 Il2CppDumper 路线"
                conf = "high"
            else:
                verdict = "Unity IL2CPP（metadata 缺失/加密）—— 先脱壳/内存 dump 再 Dumper"
                conf = "medium"
            impacts = [
                "jadx/apktool 只能看到 UnityPlayerActivity 胶水代码，游戏逻辑在 libil2cpp.so",
                "改 smali 对游戏逻辑无效 —— 判定点在 native 层",
                "apk 体积大是 Unity 资源所致，与加壳无关",
            ]
            strategies = [
                "Il2CppDumper libil2cpp.so global-metadata.dat → dump.cs 里 grep 卡密语义",
                "dump.cs 拿方法 RVA → 010Editor patch libil2cpp.so（MOV W0,#1 + RET 恒真）",
                "metadata 加密时先 BlackDex 脱壳或 Zygisk-Il2CppDumper 运行时 dump",
                "完整 playbook 见 references/unity-il2cpp.md（必读）",
            ]
        else:
            verdict = "Unity Mono —— Assembly-CSharp.dll 可直接反编译修改"
            conf = "high"
            impacts = ["C# 逻辑在 assets/bin/Data/Managed/*.dll，用 dnSpy 直改即可"]
            strategies = [
                "提取 assets/bin/Data/Managed/Assembly-CSharp.dll → dnSpy 搜 Verify/License/Card",
                "dnSpy 编辑方法恒返回 true → 替换回 APK → 对齐 + 签名",
                "若 DLL 头部非 MZ（被加密）→ 转 IL2CPP 路线思路，先脱壳",
                "完整 playbook 见 references/unity-il2cpp.md",
            ]
    elif hard:
        verdict = "Android 加固壳：" + "; ".join(hard[:3])
        conf = "high" if len(hard) >= 2 else "medium"
        impacts = [
            "apktool/jadx 直接解出的是壳外壳，看不到真实卡密逻辑",
            "改 smali 重打包大概率失败（壳会校验 dex / 签名）",
            "需先内存脱壳拿真实 dex，再定位判定点",
        ]
        strategies = [
            "Xposed 脱壳模块 / 反射大师 dump 内存 dex（代价最低，优先）",
            "adb 读 /proc/<pid>/maps 定位 dex 区段后用 dd 手工 dump（需 root）",
            "脱壳后合并 dex → jadx 读逻辑 → smali patch → 需处理壳的签名校验",
            "若改判定点代价高，改走运行时 Hook（不重打包，规避壳校验）",
        ]
    elif soft or obf or weak:
        verdict = "资源型大包 / 弱特征，未命中加固强特征 —— 大概率无壳，必须人工复核"
        conf = "low"
        impacts = [
            "dex 占比小是因 assets/res 资源占大头（游戏资源、模型、地图），不等于被加密隐藏",
            "复核 1：AndroidManifest 的 application 是业务 Application 还是 Stub/Proxy",
            "复核 2：apktool d + jadx 能否直接读到可读业务代码",
            "复核 3：dex 中能否看到卡密明文 / 验证域名（能看到即真实逻辑未隐藏）",
            "复核 4：是否存在 lib/*.so；无 so 且无壳桩时，基本排除加固",
            "重打包前注意 v1/v2 签名，需 apksigner 重新签名",
        ]
        strategies = [
            "apktool d + jadx 直读，确认读得到真实业务逻辑再决定 patch 路线",
            "对照证据逐条人工复核，不要只看置信度下结论",
            "确认无壳后直接 smali patch + 重打包 + 重签（不依赖任何注入框架）",
        ]
    else:
        verdict = "未发现明显加固特征（可尝试直接反编译）"
        conf = "low"
        impacts = ["仍可能有运行时自校验 / 签名校验"]
        strategies = ["apktool d + jadx 直读，搜卡密关键词",
                      "确认是否有签名校验（重打包后能否启动）"]

    impacts = extra + impacts
    report("APK 分析结果", verdict, conf, evidence, impacts, strategies)
    return {"type": "APK", "verdict": verdict, "confidence": conf,
            "evidence": evidence, "dex_count": len(dexes), "so": sos[:20]}


# ----------------------------------------------------------------- ELF

def scan_elf(path):
    with open(path, "rb") as f:
        data = f.read()
    evidence = []
    names = []
    if data[:4] != b"\x7fELF":
        print("[-] not ELF")
        return None
    if b"UPX!" in data:
        names.append("UPX(ELF)")
        evidence.append("字节签名 UPX! -> ELF 加壳")
    ent = entropy(data[: min(len(data), 1 << 22)])
    print("[+] ELF entropy: %.3f" % ent)
    if ent > 7.0:
        evidence.append("整体熵 %.2f 偏高" % ent)
    verdict = " / ".join(names) if names else "无明显加壳"
    report("ELF 分析结果", verdict, "medium" if names else "low", evidence,
           ["需确认是否为 native 校验主体"],
           ["IDA 定位 RegisterNatives / 导出函数", "按偏移 patch 返回值或 Xposed Hook 验证"])
    return {"type": "ELF", "verdict": verdict, "evidence": evidence}


# ----------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description="加壳/混淆/反调试检测")
    ap.add_argument("target")
    ap.add_argument("--json", dest="json_out")
    ap.add_argument("--deep", action="store_true", help="额外做混淆与载荷分析")
    args = ap.parse_args()

    p = args.target
    if not os.path.exists(p):
        print("[-] not found: %s" % p)
        return 2

    print("[+] target: %s (%d bytes)" % (p, os.path.getsize(p)))
    with open(p, "rb") as f:
        head = f.read(4)

    res = None
    if head[:2] == b"PK":
        try:
            res = scan_apk(p, args.deep)
        except zipfile.BadZipFile:
            print("[-] bad zip")
    elif head[:2] == b"MZ":
        res = scan_pe(p, args.deep)
    elif head[:4] == b"\x7fELF":
        res = scan_elf(p)
    else:
        print("[-] unsupported format (head=%r)" % head)

    print("\n[*] 自动结论仅供定性，必须人工复核后再进入 S2 方案。")
    print("[*] S1 分析未出报告前，禁止动手改文件（S3）。")

    if args.json_out and res:
        os.makedirs(os.path.dirname(os.path.abspath(args.json_out)), exist_ok=True)
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(res, f, ensure_ascii=False, indent=2)
        print("[+] json written: %s" % args.json_out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
