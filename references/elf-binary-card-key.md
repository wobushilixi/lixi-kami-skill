# ELF / so 卡密验证逆向（native 层）

适用：卡密判定写在 `.so`、APK 内置 ELF、`payload` 可执行文件、内核 `.ko` 里——Java 层改不动时。

## 一、定位门控：三步法

```bash
# 1) 先找验证结果字符串（最快入口）
python scripts/elf_patch.py <elf> --str auto
python scripts/elf_patch.py <elf> --str "验证成功"

# 2) 拿字符串地址 → 在 Ghidra/IDA 里查 xref（交叉引用）→ 往回找最近的 CBZ / B.cond
# 3) 用地址精确定位分支指令
python scripts/elf_patch.py <elf> --addr 0x0a8db54 --size 64      # 只看
python scripts/elf_patch.py <elf> --addr 0x0a8db54 --to-next --out patched.elf   # 改
```

若文件未 strip，可直接按符号名（支持 C++ 反修饰与模糊匹配）：

```bash
python scripts/elf_patch.py <elf> --func "cloud::login"
python scripts/elf_patch.py <elf> --func login        # 找不到会给候选列表
```

## 二、aarch64 门控指令速查

| 指令 | 编码要点 | 语义 |
|---|---|---|
| `cbz w8, #fail` | `sf=0, [30:25]=011010, [24]=0, imm19, Rt` | 状态字为 0 → 跳失败 |
| `cbnz xN, #fail` | `sf=1` 同上 | 非 0 → 跳失败 |
| `b.eq #fail` | `[31:24]=01010100, imm19, [4]=0, cond` | 条件失败 → 跳转 |
| `b #imm` | `[31:26]=000101, imm26` | 无条件跳转 |

## 三、**关键：不要无脑 NOP 分支**

真实案例（`起源.apk` 内置 payload，实测记录）：

```asm
0x0a910dc  bl   login          ; 返回值 w0
0x0a910e0  cmn  w0, #1         ; w0 == -1 ?
0x0a910e4  b.eq #0xa915a8      ; ← 失败清理分支（可 patch）
0x0a910e8  mov  w9, #0x101     ; ★ 成功后续：写状态字
0x0a910ec  strh w9, [x8]      ; ★ 会话/状态初始化
```

把 `b.eq` 直接 NOP 掉会让 **成功后续的状态字写入与初始化不执行**，表现为"卡住、状态不刷新、功能不完整"——比验证失败更难排查。

**正确做法**：把失败分支改成 `b #(pc+4)`（无条件执行下一条），失败分支被跳过、成功后续完整保留。

```bash
python scripts/elf_patch.py <elf> --addr 0x0a910e4 --to-next --out patched.elf
```

何时可以 NOP：当失败分支之后**只是**错误处理（弹窗/退出），没有状态写入与初始化。判断依据是看跳转目标的相邻指令（`adrp/str/mov`）。

## 四、ELF 常见坑

| 坑 | 说明 |
|---|---|
| PIE 偏移 | `ET_DYN` 且 `PT_LOAD` 的 `offset == vaddr` 时，**文件偏移 = 运行地址**；否则需做偏移映射（脚本按节表自动处理） |
| 被 strip | 符号表没了，只能按地址 + 字符串 xref 定位（`--str` + `--addr`） |
| ARM32 / Thumb | Thumb 指令 2 字节对齐，脚本按 4 字节步进会漏；需按实际架构调整 |
| x86_64 宿主 | 目标若是 aarch64 产物，x86/x86_64 模拟器**跑不了**，必须 arm64 真机 |
| 内核 `.ko` | 多数无完整 symtab；且需与内核版本匹配，用户态无法直接执行 |
| 静态链接大二进制 | 上百 MB 很常见（PhysX/ImGui/mbedtls/openssl 静态链入），反汇编要留耐心，但未 strip 时定位成本不高 |

## 五、验证

```bash
python scripts/elf_patch.py patched.elf --addr 0x0a8db54 --size 8   # 确认已变成 b
#  真机侧：把 payload 推到设备执行，看是否输出预期字符串
```

改完后必须核对：**被改指令的原始上下文是否与"验证成功"分支一致**——改错分支会引入比原版更难查的问题。
