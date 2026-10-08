# 加密 Shell 脚本逆向（sh 加密家族全解）

> 来源：逆向用户收集的 7 个开源 sh 加密工具总结（RX/ZF/龙茶/铭白/EON/Super/春秋），样本在 `F:\破解and逆向分析\加密逆向学习`。
> 一句话本质：**所有 sh 加密 = 自解压 loader + 多层编码链载荷**。不管套多少层、加多少 emoji 威慑注释，最终都要还原明文交给 `sh` 执行——这就是不可绕过的破绽。

## 0. 两条必胜路线

| 路线 | 做法 | 适用 |
|---|---|---|
| **A 静态剥壳** | `python scripts/sh_unpeel.py 加密.sh` 自动逐层剥（hex/b64/gzip/bzip2/ROT13/tar/XOR/自截取），`--show-lines` 看loader 关键行 | 编码链类（90% 工具） |
| **B 运行时截获** | loader 必然把明文写到 tmp 再执行：`/sdcard/tmp/$$`、`/data/tmp/$$`、`$TMPDIR`。执行瞬间抓文件，或改 loader 在写文件处停 | 自定义加密/ELF exec 桩（春秋） |

**卡密场景**：外挂分发常用加密 sh 包裹卡密验证逻辑（含内置卡密验证的二进制载荷，见 `apk-embedded-binary-card-key.md`）。剥开明文 sh 后：搜卡密关键词 → 走常规 sh/ELF 卡密流程。

## 1. 七大加密家族速查（识别 → 破法）

| 家族 | 加密思路 | 识别特征 | 破法 |
|---|---|---|---|
| **RX / RX-KernelX** | gzip/bzip2 多级压缩 + b64 + hex→str，eval 分层解 | `eval "$(__rx_h2s`、`base64 -d \| bzip2 -dc`、`gzip -cd \| tr -d` | sh_unpeel 自动剥；注意 bzip2 与 gzip 嵌套顺序 |
| **ZF加密** | gzip→b64→tar.gz→hex→b64→tar.gz→hex **套娃编码** + emoji 乱码干扰注释 | `tail -n +N "$0" \| tar -xzvf`、大量 emoji + 「不要逆向」威慑串 | sh_unpeel 自动剥（tar 解包取最大文件）；干扰行被 strip_junk 剔除 |
| **龙茶** | 函数嵌套混淆（`__outer/__inner/__run/_f0.._f4`）+ b64+gzip+hex + `strip_junk` 垃圾字符剔除 | 大量 `_fN()` 函数、`get_payload`、`strip_junk` | 先读 `strip_junk` 的剔除表，手工剔除后 sh_unpeel 接管；或运行时截获 `$TMPDEC` |
| **铭白V10** | **ROT13 变换夹心**：b64→ROT13→b64 + `xxd -r -p`+gunzip | `base64 -d \| tr 'N-ZA-Mn-za-m' 'A-Za-z' \| base64 -d`、`tail -n +14 "$0"` | sh_unpeel 的 ROT13 候选层自动处理；ROT13 字符集可自定义变体——从 loader 里抄 `tr` 映射表 |
| **EON** | b64 多层 + `openssl rand -hex` 随机盐 | `NEO第一代加密`、`openssl rand -hex` | 盐通常拼进编码串头部定长位置，读 loader 确定偏移后剥 |
| **Super加密5.0** | 16 字节 urandom key **循环 XOR** + hex；key 明文存产物内 | 产物含 `bash🔒` 标记；其后 32 hex = key，再后 = 密文 hex | sh_unpeel 秒破（key 就在文件里）；源码证实 `ciphertext[i]^key[i%16]`，前缀 `set +x\n{\n` 亦可当已知明文推 key |
| **春秋Shell加密** | aarch64 ELF exec 桩（`chunqiu_exec`）+ `libhook.so`，运行时解密落地 | ELF 文件头 + 附带 .so | 静态剥不了 → 路线 B：root 下 `strace -f -e trace=openat,write` 跑一次，看它写了哪个 tmp 文件；或内存 dump（`gcore` / `/proc/pid/mem`） |

> Super加密源码（`jni/加壳器.c`）还证实：`XC()`×几十次纯刷屏干扰、环境校验只认 MT/Termux 的 PATH——改 PATH 或直接静态破都无视。**威慑文字 ≠ 加密强度**。

## 2. 通用剥壳循环（sh_unpeel.py 的原理，手剥时照此顺序）

```
循环：
 1. 数据含 bash🔒 标记?        → 拆 key(32hex)+密文hex → 16字节循环XOR
 2. loader 有 tail -n +N?     → 从第 N 行截取载荷
 3. 全 hex?                   → xxd -r
 4. 全 b64 字符集?            → b64 decode（先试原样，再试 ROT13 后）
 5. gzip(1f8b)/bzip2(BZh)/zlib(78 9c)? → 解压
 6. tar/ustar?                → 解包取最大成员
 7. 明文脚本(#!开头/eval逻辑)?  → 结束
 8. 都不是                     → 剔除注释/emoji 垃圾行后重试 → 仍不行 → 路线 B
```

多候选歧义（如 ROT13 后仍是合法 b64 字符集）按**产出评分**选：脚手本 > 已知 magic > 可打印 > 乱码。

## 3. 运行时截获命令速记（路线 B）

```bash
# 看它落地了什么文件（root/termux）
strace -f -e trace=openat,write ./加密.sh 2>&1 | grep -E "tmp|dec|run"
# 执行瞬间另一终端抢文件
watch -n 0.1 'cp /data/tmp/*/ZF.dec /sdcard/out.sh 2>/dev/null'
# ELF 桩（春秋）：内存 dump 后搜明文
gcore $(pidof chunqiu_exec); strings core.* | grep -A5 "kami\|卡密\|#!/"
```

## 4. 与 lixi-nixiang-skill 主流程的衔接

- **S1**：`packer_detect.py` / 1.2b 节发现 `assets/` 或下发目录有加密 `.sh`（头部无 `#!/`、大段 hex/b64/emoji）→ 先 `sh_unpeel.py` 剥壳再分析
- **S2**：加密 sh 内嵌 ELF 载荷 → `apk-embedded-binary-card-key.md`；纯 sh 卡密逻辑 → 直接 patch 明文
- **S3**：改完明文后不需要重新加密——替换 loader 引用的载荷或直接投喂明文脚本
- **S4**：`node --check` 不适用；`sh -n 明文.sh` 语法检查
