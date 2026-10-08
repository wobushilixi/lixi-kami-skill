# Unicorn 离线仿真：无设备 / 无 Frida 时把校验函数跑起来

> **解决什么问题**：本机安卓端 Frida 不可用、又没有 root 真机时，A 类（纯本地算法）目标过去
> 只能靠静态推断 + S4 三条闭环收口，判定点对不对、补丁起没起作用全靠"逻辑自证"。
> 有了 `scripts/emu_check.py`，可以在 PC 上把 `.so` / payload 里的**校验函数原样执行**，
> 拿到真实的返回值 —— 判定点定位和补丁语义从此有**行为级证据**，不再只是推断。

## 一、能力矩阵（2026-10-08 实测口径）

| 能力 | 状态 | 说明 |
|---|---|---|
| arm64 ELF 装载（PIE/EXEC，段+重定位） | ✅ 实测 | RELATIVE / JUMP_SLOT / GLOB_DAT / ABS64 |
| 函数定位 | ✅ 实测 | `--sym`（.symtab → .dynsym，支持子串）或 `--func 地址` |
| 参数注入 | ✅ 实测 | cstr / ptr_len / int / ints / **jni_str / jni_mix** |
| 返回值 + 内存 dump | ✅ 实测 | w0/x0 + `--dump x0:64`（看不含 NUL 的字符串/缓冲区） |
| **补丁差分验证** | ✅ 实测 | `--patch` 前后同一输入返回不同 → 补丁语义被证实 |
| 崩溃定位 | ✅ 实测 | 自动打印故障前最后 14 条指令（反汇编）+ x0–x7 |
| 假 JNIEnv | ✅ 实测 | 函数表桩 + GetStringUTFChars/NewStringUTF/FindClass/ThrowNew 等 |
| 依赖库真实执行 | ⚠️ 实验 | `--dep libc++_shared.so`：std 库代码真实跑，但**跨库 sret 的复杂 C++ 会到边界** |
| libc 模拟 | ✅ 30+ 函数 | strlen/strcmp/memcpy/malloc/…（见脚本 docstring） |
| 网络系调用 | ⚠️ 固定失败 | socket/connect/… 一律 -1：**联网分支可预测地走失败路径**，可观察错误分支 |

**已验证的实测记录（2026-10-08）**
1. 合成 aarch64 校验函数（keystone 汇编）：`"ABC"`→1、`"XX"`→0；
   `--patch` 把 `mov w2,#0x41` 改成 `#0x58` 后同一输入 `"XX"`→1 → **差分链路成立**。
2. 真实目标 `libcardverify.so`（从卡密 APK 提取）：
   - `--list` 正常列出 221 个导入 / 混淆导出，定位到真入口
     `Java_com_emnb_a666_util_CardVerifyHelper_nativeVerify`；
   - 无依赖运行：960 条指令跑完（`STOP reason=ret`）——**真实混淆代码可执行**；
   - 加载 `libc++_shared.so` 依赖：真实 std::string 代码被执行，
     最终卡在**包内不存在的辅助库符号** `L__0x9Qq(...)`（该目标跨库，缺库无法补），
     崩溃点被自动定位到具体指令与寄存器值。

## 二、标准工作流（A 类目标）

```bash
S="<skill>/scripts"

# 1) 找目标函数
python $S/emu_check.py --elf libfoo.so --list
python $S/emu_check.py --elf libfoo.so --list | grep -iE "verify|check|card|kami|jni"

# 2) 跑一次看行为（JNI 入口用 jni_str；内部 C 函数用 cstr）
python $S/emu_check.py --elf libfoo.so --sym check_key --arg "TEST-KEY"
python $S/emu_check.py --elf libfoo.so --dep libc++_shared.so \
  --sym Java_xxx_nativeVerify --arg-mode jni_str --arg "TEST-KEY" --arg "MACHINE-001"

# 3) 判定点定位自证：无效输入必须返回"失败"
python $S/emu_check.py --elf libfoo.so --sym check_key --arg "BAD" --expect 0

# 4) 补丁差分：同一输入，打完补丁必须翻转
python $S/emu_check.py --elf libfoo.so --sym check_key --arg "BAD" --expect 1 \
  --patch 0x1A2C4:1f2003d5        # 地址填 IDA 里看到的文件内地址，脚本自动加 base

# 5) 看函数写出的内容（解密串、生成的码）
python $S/emu_check.py --elf libfoo.so --sym gen_code --arg-mode int --arg 12345 --dump x1:64

# 6) 小空间搜索：接受集（如 4 位码）— 外层 shell 循环 + --expect
for i in $(seq 0 9999); do
  python $S/emu_check.py --elf libfoo.so --sym check --arg-mode int --arg $i --expect 1 >/dev/null && echo "HIT $i"
done
```

**在 S1/S3/S4 里的落点**
- S1：用仿真确认"哪个函数是真判定"（改输入看返回值变化），把候选判定点从 E# 升为已证实；
- S3：补丁先用 `--patch` 在仿真里试，翻转再落到文件（**先仿真后落盘**，避免反复重打包）；
- S4：无设备时给"补丁字节复核"补上**行为级差分证据**（第 4 步），比单看字节强一档。

## 三、局限（如实对待，别当万能）

| 局限 | 表现 | 应对 |
|---|---|---|
| 跨库依赖缺失 | 卡在包内不存在的导入（如 `L__0x9Qq`），报 unmapped + 最后指令 | 把同包的其它 .so 用 `--dep` 加载；仍缺则该目标仿真只能到边界 → 真机/mock |
| 复杂 C++（libc++ 全链路） | 加载 libc++ 后仍可能因某个未模拟 JNI/环境返回走偏 | `--dep` + 观察 `未模拟导入/JNIEnv 编号` 清单；数量多则降置信度 |
| 加密初始化 / 需真实文件网络 | 函数入口就依赖运行时解密或真实 IO | 不适合离线仿真 → 走真机路线 |
| TLS / 线程 | 已给零页 TLS + canary；复杂 pthread/TLS 仍可能异常 | 报 `stack_chk_fail` 即视为不可信 |
| 结果失真不报错 | 未模拟导入返回 0 时，函数可能"正常返回但答案是错的" | **看结尾的未模拟清单**；清单非空 → 结果只用于差分，不用于绝对结论 |

**差分模式的鲁棒性**：即使有未模拟导入，只要两次运行（打补丁前后）除补丁外条件相同，
输出差异仍然可信 —— 这是缺库目标也能用的理由。

## 四、环境准备

```bash
python -m pip install unicorn keystone-engine      # 一次即可（本机已装：unicorn 2.1.4）
```
- `capstone` 用于反汇编（本机 5.0.7 已有）。
- 纯离线、不联网、不发包；只读目标文件，`--patch` 只改仿真内存，不动磁盘文件。
