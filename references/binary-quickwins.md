# 二进制卡密 Quick Wins 与高级模式（EXE / ELF / DLL / 特殊格式）

> 来源：融合 haikow/claude-reverse-skills 的 reverse-engineering skill（field-notes / patterns / anti-analysis）。
> 定位：S1 定位判定点与 S3 patch 的加速手册。优先试 Quick Wins，都失败再上重型分析。

## 0. Quick Wins 漏斗（按顺序试，多数目标在前三步就破）

```bash
# 1. 明文即答案：一半的简单 crackme 直接搜字符串
strings target | grep -iE "key|serial|valid|licen|success|fail|flag|secret|password"
rabin2 -z target | grep -i "valid"        # PE/ELF 通用
objdump -s -j .rodata target | less       # 期望值表通常在比较指令附近，长度=卡密长度

# 2. 动态观察不逆向：ltrace/strace 直接看比较
ltrace ./target                            # Linux: 看 strcmp/memcmp 实参
strace -f -s 500 ./target                  # 看系统调用层行为

# 3. 测试输入喂进去
./target AAAA-AAAA-AAAA
echo "test" | ./target

# 4. 多反编译器交叉对照（dogbolt.org 免费在线：IDA/Ghidra/ BinaryNinja 同时出码）
#    一个反编译器看不懂的地方换个编译器常秒懂

# 5. 符号执行自动解（angr，适合"找满足条件的输入"类）
python -c "
import angr
p = angr.Project('./target', auto_load_libs=False)
s = p.factory.entry_state()
sim = p.factory.simgr(s)
sim.explore(find=lambda st: b'correct' in st.posix.dumps(1),
            avoid=lambda st: b'wrong' in st.posix.dumps(1))
print(sim.found[0].posix.dumps(0))  # 解出的卡密输入
"
#    提速技巧：约束输入为可打印 ASCII + 已知前缀；hook 掉昂贵函数（加密/IO）防路径爆炸

# 6. 跨平台模拟（Qiling）：异架构/反调试重的一律模拟跑，无调试器痕迹
```

## 1. 三个决定成败的判读规则

### 1.1 诱饵目标识别（Decoy Flag Detection）

**模式**：真实判定前有多个假比较目标（各自带不同的成功提示）。看到连续多个比较串/成功分支时——
**在最终比较处下断**（最后一个），不是第一个。判断依据：比较目标不止一个 + 成功消息文本不同。

### 1.2 比较方向（Critical，方向搞反=白算）

| 模式 | 判定代码形态 | 还原动作 |
|---|---|---|
| `transform(input) == stored` | 拿你输入做变换去比常量 | **逆转变换**还原输入 |
| `transform(stored) == input` | 拿常量做变换生成期望值 | **正向应用变换**到常量（不用逆向！） |

先分辨方向再动手：看变换函数作用在**输入指针**还是**常量指针**上。

### 1.3 内存 dump 策略（让程序替你算）

**核心洞见**：不还原算法，让程序自己算出答案然后偷看——
在最终比较处断下（`b *main+OFFSET`），输入任意等长字符串，直接 dump 参与比较的寄存器/内存（`x/s $rsi`）。适用于一切"输入必须等于某个派生值"的校验。

进阶：INT3 补丁 + coredump——在变换输出后写 `0xCC`，开 coredump，逐字符爆破时从 coredump `strings` 提取计算状态，完全绕开逆向变换本身。

## 2. 常见卡密算法模式速查（看到常量直接认领）

| 线索常量/形态 | 算法 | 破法 |
|---|---|---|
| 单字节 XOR，256 次试完必中 | XOR 单字节 | 已知明文攻击（卡密前缀通常已知） |
| `^ i` / `^ (i & 0xff)` 分层 | 位置索引 XOR | 逐位置逆 |
| `0x9E3779B9` / `0x2545F491` | Xorshift/TEA 族 | 认领算法直接逆 |
| RC4 且 key 在 rodata | RC4 硬编码 key | 提 key 直接解 |
| S-Box 表（256 字节常量表） | 自定义置换/流密码 | 表即密钥，逆查表 |
| `0x1b` 伴随乘法 | GF(2^8)（AES 多项式） | 高斯消元解方程 |
| hex 字符串比较 | hex 编码比较 | `xxd -r -p` 解码 |
| 逐字节计时差异 | 时序侧信道 | 逐字符测耗时恢复 |
| 前缀哈希逐段校验 | 前缀独立哈希 | 逐字符恢复 |

## 3. 特殊格式目标（别认错格式就死磕）

| 格式 | 识别特征 | 工具路线 |
|---|---|---|
| **Flutter (Dart AOT)** | `libapp.so` + `libflutter.so` | **Blutter**：`python3 blutter.py lib/arm64-v8a out_dir` 输出还原的 Dart 符号 |
| Python 打包（pyinstaller/pyc） | `PYZ` / `MEI` / `.pyc` | uncompyle6 / pycdc（3.9+ 需自己编译）；Pyarmor 加固 → Pyarmor 静态脱壳 |
| .NET / Unity Mono | CLR 头 / `Assembly-CSharp.dll` | dnSpy 调试+改 / ILSpy 反编译 |
| UPX 壳 | UPX 节名 | `upx -d`；解不开=魔改头，对照 UPX 源码找被改字段 |
| WASM | `\0asm` 头 | `wasm2wat` 转文本改比较 → `wat2wasm` 回写 |
| Tauri 桌面应用 | Rust+内嵌前端 | 找 `index.html` xref → dump Brotli 压缩的前端资源 → 转前端 JS 逆向 |
| Electron | `app.asar` | asar 解包 → 前端 JS → 搜验证逻辑 |
| Go 静态二进制 | `go.buildid` | GoReSym 恢复符号（strip 也有效）；字符串是 {ptr,len} 对非零结尾 |
| Rust | `core::panicking` / `_ZN` 符号 | `rustfilt` demangle；`strings \| grep panicked` 拿源码路径行号最快 |
| 损坏 ELF 节表（反分析） | readelf 报错但程序能跑 | 节表可弃，按 **program header**（`readelf -l`）分析；把 `e_shoff` 置零也行 |

## 4. 反分析对抗速查（详表见 anti-defense.md）

- **opaque predicate / 花指令**：永真/永假条件 + 垃圾字节骗反汇编器 → patch 成 nop，或换个反汇编器
- **自校验（.text CRC）**：patch 前先确认校验点，否则改完运行即崩
- **信号流控制**：SIGFPE handler 隐式跳转，静态看不见 → `strace -e signal=SIGFPE` 数信号做侧信道
- **fork+pipe 死分支**：真逻辑在永假分支里 → strace 认出 fork/pipe 模式，patch 比较常量
- **无导入表但行为复杂**：运行时哈希解析 API → 别逆哈希，LD_PRELOAD hook 顶层函数直接拿明文

## 5. radare2 patch 速查（本机已装：`C:\Users\Administrator\tools\radare2\...\bin\radare2.exe`）

```powershell
rabin2 -I t.exe        # 架构/信息
rabin2 -zz t.exe       # 全字符串
r2 t.exe               # 交互
  aaa                  # 分析
  afl                  # 函数列表
  iz~valid             # 搜字符串
  axt @ <addr>         # 交叉引用（谁在比较这个串）
  pdf @ main           # 反汇编
  s 0x401000           # 跳地址
  wa jmp 0x401200      # 汇编写入
  wx 9090              # 写十六进制
  wq                   # 保存退出
r2 -w t.exe            # 写模式
radiff2 -C old.exe new.exe   # 新旧版本 diff（老版本没防线时直接抄老版本的判定点位置）
rasm2 -a x86 -b 64 "nop"     # 单条汇编编码
```

## 6. 版本对照补丁（同 App 老版本没防线时的捷径）

radiff2 / BinDiff / Diaphora / dogbolt 对照新旧二进制：
- 新版加的校验 = diff 出的新增函数 → 重点打
- 老版本裸奔的判定点地址迁移 → 从老版`比较常量`在新版搜同值

## 7. 证据纪律

- 每个判定点标 E#（地址 + 证据类型：字符串引用/比较指令/交叉引用）
- Quick Wins 每一步失败都记录，**失败的路径也是排除证据**
- 连续 2 次无依据盲试 → 强制回 S1（沿用 SKILL.md 禁令二）
