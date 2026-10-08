// ghidra_java_template.java - Ghidra headless Java postScript 模板（Ghidra 12+ 用 Java，不依赖 PyGhidra）
//
// 为什么用 Java 版：Ghidra 12 弃用 Jython，.py postScript 需要 PyGhidra 环境；
// headless 下报 `Python is not available` 且 postScript 根本没执行（白等）。
// .java 脚本由 Ghidra 原生编译，无需 Python 环境。
//
// 用法（headless）：
//   analyzeHeadless.bat <proj_dir> <proj_name> -import target.elf \
//     -scriptPath <本文件所在目录> -postScript ghidra_java_template.java "关键词1,关键词2" \
//     -deleteProject
//
// 建议搭配：先用 python 检查「ELF+尾部追加高熵载荷」并 dd 截断（只保留段表覆盖区）再喂 Ghidra，
// 否则追加载荷会被当指令扫描，auto-analysis 卡死（实测 Box免费加固 1.38MB 载荷拖死 30 分钟无产出）。
//
// 输出：把入口点 / 关键词命中字符串及其引用函数 / 指定函数调用者 打到 stdout，可直接落盘做证据。
// 类名必须与文件名一致（Ghidra 要求），本文件类名 ghidra_java_template 为非法 Java 标识符，
// 请复制为 GhidraAll.java 并把类名改成 GhidraAll（一次 sed 即可）。

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.SourceType;

import java.util.Locale;

public class GhidraAll extends GhidraScript {

    @Override
    protected void run() throws Exception {
        String[] keywords = getKeywords();

        println("=== ghidra_java_template start ===");
        println("program   = " + currentProgram.getName());
        println("format    = " + currentProgram.getExecutableFormat());
        println("imageBase = " + currentProgram.getImageBase());
        println("lang      = " + currentProgram.getLanguageID());
        println("md5       = " + currentProgram.getExecutableMD5());

        // 1) 入口点概览
        println("\n--- entry points ---");
        for (Address a : currentProgram.getSymbolTable().getExternalEntryPointIterator()) {
            println("entry: " + a);
        }

        // 2) 关键词命中字符串 + 引用它的函数（卡密/授权/协议逆向的定位主力）
        println("\n--- keyword hits (define strings / xref functions) ---");
        Listing listing = currentProgram.getListing();
        DataIterator dit = listing.getDefinedData(true);
        int hits = 0;
        while (dit.hasNext() && !monitor.isCancelled()) {
            Data d = dit.next();
            if (!d.hasStringValue()) {
                continue;
            }
            Object v = d.getValue();
            String s = (v == null) ? "" : v.toString();
            String low = s.toLowerCase(Locale.ROOT);
            for (String kw : keywords) {
                if (kw.isEmpty() || !low.contains(kw)) {
                    continue;
                }
                hits++;
                println(String.format("[hit] %-40s @ %s  \"%s\"",
                        kw, d.getAddress(), s.length() > 80 ? s.substring(0, 80) + "..." : s));
                // 谁引用了这个字符串 → 大概率就是判定点所在函数
                ReferenceIterator refs =
                        currentProgram.getReferenceManager().getReferencesTo(d.getAddress());
                while (refs.hasNext() && !monitor.isCancelled()) {
                    Reference r = refs.next();
                    Function f = listing.getFunctionContaining(r.getFromAddress());
                    if (f != null) {
                        println(String.format("       used-by %s @ %s (from %s)",
                                f.getName(), f.getEntryPoint(), r.getFromAddress()));
                    } else {
                        println("       ref-from " + r.getFromAddress());
                    }
                }
                break; // 一条字符串只报一个关键词
            }
        }
        println("[total hits] " + hits);

        // 3) 导出「小函数」清单：短函数常是校验/取值函数（size 可由 body 估算）
        println("\n--- small functions (candidate checkers) ---");
        int shown = 0;
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (monitor.isCancelled() || shown > 60) {
                break;
            }
            long sz = f.getBody().getNumAddresses();
            if (sz > 0 && sz <= 64) {   // 16 条指令以内
                println(String.format("0x%-10s size=%-4d %s",
                        f.getEntryPoint(), sz, f.getName()));
                shown++;
            }
        }

        // 4) 给命中函数打标记（改名 + 注释），便于在 GUI 里二次分析
        //    按需打开：把候选函数名统一加前缀，避免与原始符号混淆
        // for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
        //     if (f.getName().contains("check")) {
        //         f.setName(f.getName() + "_CANDIDATE", SourceType.USER_DEFINED);
        //         setPlateComment(f.getEntryPoint(), "candidate: verify keyword hit");
        //     }
        // }

        println("=== ghidra_java_template done ===");
    }

    /** 第一个脚本参数：逗号分隔关键词；不给则用默认集 */
    private String[] getKeywords() {
        String[] args = getScriptArgs();
        if (args.length > 0 && !args[0].isBlank()) {
            return args[0].toLowerCase(Locale.ROOT).split(",");
        }
        return new String[]{
                "card", "kami", "key", "verify", "auth", "license", "expire",
                "signature", "machine", "token", "激活", "卡密", "授权", "验证"
        };
    }
}
