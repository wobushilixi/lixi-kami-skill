# Android 环境检测对抗（Root / 框架 / 模拟器 / 反作弊）

> **为什么卡密绕过必须管这一层**：外挂、辅助、游戏工具类 App 常带环境检测。卡密改成功了，但 App 检测到 Root / 框架 / 模拟器就拒绝启动、闪退或限制功能——等于白改。
> **真机实测前，先过这一关。**
> 深度资料见 `F:\知识库\Root知识库`（75 篇，4.5 万行），本文是提炼版。

## 一、先判断目标用了什么

```bash
# 看 lib 目录有没有安全组件
unzip -l target.apk | grep -iE "tersafe|SGMainSo|SGSafeSo|tp2|secshell|jiagu"
# 看 dex 里有没有检测特征
python scripts/kami_scan.py target.apk --top 20
```

| 特征 | 说明 |
|---|---|
| `libtersafe2.so` / `libtersafe.so` + `tp2.jar` | 腾讯 TP2 系（老游戏常见） |
| `libSGMainSo*.so` / `libSGSafeSo*.so` | 新一代腾讯 ACE 安全组件 |
| `libjiagu` / `libsecshell` / `libexecmain` 等 | 加固壳（先脱壳，见 `packer-analysis.md`） |
| 启动时连 `cs.*.anticheat.com` / `*.gamesafe.qq.com` | **连接服务器，绝不能封**（封了必卡登录） |

## 二、检测面 × 修复对照

### A. Root 与 Magisk 特征

| 检测点 | 原理 | 修复 |
|---|---|---|
| su 二进制 / 超级用户包名 | 扫 PATH、`/data/adb`、已知包名 | Zygisk Next denylist + SUSFS `sus_path`；HideMyApplist 挡包名枚举 |
| Magisk 管理器包名 | 扫 `com.topjohnwu.magisk` | Magisk App 改随机包名 + 藏入 HMA |
| Magic Mount 挂载痕迹 | 读 `/proc/self/mounts` 找 magisk 字样 | ZN「仅还原挂载」模式，或 SUSFS `try_umount` + `sus_mount` |
| 环境属性 | `ro.debuggable`、`ro.build.tags=test-keys` | resetprop 伪装 |

### B. 注入框架与 Hook

| 检测点 | 原理 | 修复 |
|---|---|---|
| Zygisk / Xposed 痕迹 | so 加载列表、匿名映射、companion socket | ZN 匿名内存加载；**目标进程内不要启用任何作用域模块** |
| inline hook 操作码比对 | 对自身关键函数前 N 字节做 `opcode_dismatch` 校验 | 不注入 native hook（静态 patch 反而没有这个风险——这也是本 Skill 走静态路线的好处） |
| Frida / ptrace | TracerPid 监控、默认端口、进程名 | 运行时确保无 frida-server、不附加调试 |
| GPU Profiler | 图形调试工具特征 | 关闭 GPU 调试类工具 |

### C. 模拟器与虚拟化

| 检测点 | 说明 |
|---|---|
| build 属性 `goldfish` / `ranchu` / `sdk` | 可 prop 伪装，但覆盖不全 |
| qemu 特征文件 / 设备节点 | 同上 |
| 传感器 / 通话能力缺失 | 需模拟模块，易露 |
| 云手机 / VirtualApp（uid 999x） | **服务端聚类识别，基本不可伪装** |

**结论：真机是唯一稳妥路线。** 模拟器只在纯静态验证时用，真机实测必须 arm 真机。

### D. 应用列表与周边环境

- 可疑应用枚举（检测工具、框架、多开 App）→ HideMyApplist 对目标返回空列表 / 白名单
- 开发者选项开启 → DevOptsHide / notdeveloper
- USB 调试授权状态 → 同上

### E. Play Integrity 三层

| 级别 | 含义 | 常见手段 |
|---|---|---|
| BASIC | 基础完整性 | PlayIntegrityFork（PIFork） |
| DEVICE | 设备完整性 | PIFork + 有效 keybox |
| STRONG | 硬件级证明 | TrickyStore / TEESimulator（需有效 keybox，Android 13+ 强制硬件信号） |

## 三、三档修复组合

```
基础档（普通 App）：
  Magisk v28+ 或 KSU + Zygisk Next（仅还原挂载） + HMA-OSS 白名单

标准档（腾讯系 / 带环境检测的 App）：
  基础档 + Shamiko（与 ZN 白名单模式二选一）+ PIFork(BASIC/DEVICE)
  + DevOptsHide + resetprop 伪装 ro.build.tags / ro.debuggable

强化档（强检测）：
  标准档换 SUSFS 内核级方案（SukiSU-Ultra 或带 SUSFS 的内核）
  + TrickyStore / TEESimulator（keybox 有效时 DEVICE~STRONG）
```

框架选型速记：Magisk（用户空间，生态最全）/ KernelSU 系（内核级，隐藏上限高）/ APatch（内核补丁）。KSU 分支：官方 v3.2.5（仅 GKI）、KSU Next v3.3.0、SukiSU-Ultra v4.x（内置 KPM+SUSFS，隐藏玩家主流）。

## 四、入场前自检（真机实测前 5 分钟）

```bash
# 1) 三大检测工具过一遍，目标：常规项全绿
#    Momo → Hunter → Ruru

# 2) 完整性
#    Play Integrity API Checker：至少 BASIC 通过

# 3) 进程级复查（App 运行状态下另开 shell）
adb shell su -c 'cat /proc/$(pidof <包名>)/status | grep -E "TracerPid|Name"'
#    TracerPid 应为 0
adb shell su -c 'getprop ro.debuggable'      # 应为 0
adb shell "pm list packages | grep -i magisk"  # 应为空

# 4) 网络层自查：确认 hosts/iptables 没封连接服务器（cs.*.anticheat.com / *.gamesafe.*）

# 5) 小号试水：先跑低风险场景，观察是否弹窗/秒踢/闪退
```

## 五、边界（必须如实说明）

客户端改不了的部分，不要声称能绕过：

| 维度 | 为什么做不到 |
|---|---|
| AI 行为分析（如 ACE-Replay 对局回放建模） | 服务端建模，与客户端环境无关 |
| 服务端数据密钥（关键坐标/数据每局绑硬件加密） | 本地伪造无意义 |
| 人脸 / 设备实名连坐风控 | 服务端维度 |
| 卡密的服务端复核与封禁 | 客户端绕过只对本机生效 |

**卡密绕过 + 环境隐藏 ≠ 不会被服务端封号。** 报告中要写明这一边界。

## 六、深挖路径

需要更细的原理与配置时，直接查：

```
F:\知识库\Root知识库\03-隐藏与反检测技术\    # Root 检测、Play Integrity、SUSFS、银行/游戏案例
F:\知识库\Root知识库\07-检测与对抗模块\      # Momo/Ruru/Hunter/ApplistDetector 原理与对抗
F:\知识库\Root知识库\08-实战案例\            # 王者荣耀/三角洲/CF/银行 全流程
F:\知识库\Root知识库\12-ACE对抗专题\         # ACE SDK 逐项修复、网络层边界、模拟器对抗、一键配置
F:\知识库\Root知识库\09-附录\01-术语速查表.md
```

全文带 YAML frontmatter，用 `keywords` 字段 grep 检索最快：

```bash
grep -rn "keywords" "F:/知识库/Root知识库" | grep -i "隐藏\|检测\|Play"
```
