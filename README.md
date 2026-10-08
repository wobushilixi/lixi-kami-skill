# kami-bypass

> 授权测试环境下的**卡密 / 激活码 / 授权验证**逆向与绕过 Skill。把「查壳 → 出方案 → 实施 → 验证」做成有证据、可复现、不靠运气的流程。

支持三类目标：**Android APK**（Java/smali、so、shell/加固壳）、**Windows EXE / DLL**、**网页 Web**（前端 JS 校验 / 接口验证系统）。

---

## 特性

| 特性 | 说明 |
|---|---|
| **四阶段强制流程** | `S1 分析 → S2 方案 → S3 逆向 → S4 测试`，上一阶段未达出口标准不进下一阶段 |
| **真机实测可选** | 有设备就跑三态验证；没有则用 S4 三条闭环收口（补丁字节复核 + 产物自检 + 逻辑自证），**如实标注未验证** |
| **禁止赌博式尝试** | 任何操作必须带 `E# 假设 + 依据 + 验证方式`；连续 2 次无证据支撑的失败强制停止 |
| **禁止无依据爆破** | 字典爆破默认关闭，仅「本地离线 + 明确要求 + 有成功率依据」三条同时满足才允许 |
| **交付双审** | Standards（产物合规）+ Spec（是否真解决用户的问题），两维都过才算交付 |
| **95% 置信度门槛** | ≥95% 正常交付；70–95% 须标注未验证项；<70% **不得交付** |
| **产物可安装性把关** | 对齐 / 签名 / 完整性自检，直接拦下 `INSTALL_FAILED_INVALID_APK (-124)` 这类"装不上"的坑 |

## 工作流

```
S1 分析 ──► S2 方案 ──► S3 逆向 ──► S4 测试 ──► (可选) 真机实测
  │            │           │           │
判壳与对抗层   ≥2候选      补丁落盘    对齐/签名/自检
A/B/C/D 分类   +推荐+风险   .bak 备份   补丁字节复核
E# 假设台账    +回退路径                逻辑自证
```

架构分类决定策略：**A** 纯本地算法 → 算法还原/keygen ｜ **B** 本地+服务端 → 本地 patch + 响应替换 ｜ **C** 服务端主导 → mock / 改客户端判定 ｜ **D** 试用计数 → 时间冻结 / 计数重置

## 目录结构

```
kami-bypass/
├── SKILL.md                      # 主流程：触发词、四阶段、反赌博与交付门槛
├── LICENSE                       # MIT
├── scripts/                      # 全部离线可用，纯标准库实现
│   ├── packer_detect.py          # 壳 / 混淆 / 反调试 / 签名校验 / 机器码 / 环境检测
│   ├── kami_scan.py              # APK·DEX·EXE·SO 的卡密特征扫描
│   ├── web_kami_scan.py          # 网页 / JS / HAR 的卡密与验证接口扫描
│   ├── elf_kami_gate.py          # ELF 门控定位（字符串 → xref → 分支）
│   ├── elf_patch.py              # aarch64 分支改写（--to-next / --nop）
│   ├── smali_kami_patch.py       # smali 判定点 patch（默认 replace 模式）
│   ├── verify_patch.py           # 产物自检：死代码 / 寄存器越界 / 对齐 / 签名
│   ├── zipalign4.py              # 纯 Python 对齐（不依赖 build-tools）
│   └── xposed_kami_module.java   # 可选：Xposed / LSPosed Hook 模板
└── references/                   # 按需加载的深入文档
    ├── packer-analysis.md        # 壳识别、已知误报表、方案报告模板
    ├── anti-defense.md           # 签名校验 / 反调试 / 完整性 / 机器码
    ├── android-card-key.md       # APK 卡密链路（Java / so / 加固壳）
    ├── android-env-detection.md  # Root / 框架 / 模拟器 / 反作弊对抗
    ├── apk-embedded-binary-cardkey.md  # 卡密藏在 assets 伪装 ELF 里
    ├── elf-binary-card-key.md    # ELF 门控 patch（为什么不要 NOP）
    ├── windows-card-key.md       # Windows EXE / DLL 链路
    ├── web-card-key.md           # Web 全流程（Overrides / 油猴 / mock）
    ├── bypass-playbook.md        # 手法选型、回退路径、验证规范
    ├── engineering-discipline.md # 诊断循环、交付双审、对照实验
    ├── open-source-mapping.md    # 开源分流 O1/O2/O3
    ├── external-knowledge-index.md  # 外部知识库路由
    └── beginner-kit.md           # 术语表、工具清单、12 步、报错对照
```

## 安装

把整个目录放进 skills 目录即可：

| 平台 | 路径 |
|---|---|
| WorkBuddy | `~/.workbuddy/skills/kami-bypass/` |
| ZCode | `~/.zcode/skills/kami-bypass/` |

## 使用

**启动词**：消息中出现「**李喜**」即加载本 Skill。

**预授权执行格式**：

```
李喜，文件路径，绕过卡密
```

命中该格式即进入自动执行模式：不停下来等确认，按 S1→S4 跑完；但 S1 分析、备份 `.bak`、S4 验证收口一样不能少。

也可直接说明需求，例如"这个 APK 的卡密怎么绕过""帮我还原这个 EXE 的注册算法""网页端这个验证接口改哪里"。

## 工具速查

```bash
# S1：先查壳与对抗层（首个必跑）
python scripts/packer_detect.py target.apk --json work/packer.json

# S1：扫卡密特征
python scripts/kami_scan.py target.apk --top 15

# S1：网页 / HAR
python scripts/web_kami_scan.py ./saved_site --top 15

# S3：smali 判定点（默认 dry-run，不写文件）
python scripts/smali_kami_patch.py work/smali --top 20
python scripts/smali_kami_patch.py work/smali --apply --ret true

# S3：ELF 门控
python scripts/elf_patch.py payload.elf --str auto
python scripts/elf_patch.py payload.elf --addr 0x0a8db54 --to-next --out patched.elf

# S4：产物自检 + 对齐（顺序不可颠倒：回编 → 对齐 → 签名）
python scripts/verify_patch.py rebuilt.apk
python scripts/zipalign4.py rebuilt.apk aligned.apk
python scripts/zipalign4.py check aligned.apk
```

## 配套资料（可选）

`references/external-knowledge-index.md` 里有路由表，指向本机的 Android Root 知识库、逆向知识库、reverse-skill 集合等深度资料；文中 `$ROOT_KB` / `$REVERSE_KB` / `$REVERSE_SKILL_DIR` 是占位符，换成本机路径即可。

本 Skill 的工程纪律提炼自 [mattpocock/skills](https://github.com/mattpocock/skills)（MIT）。

## 免责声明

本工具用于**已获授权**的安全研究、逆向工程与兼容性测试。使用者需确保：

- 目标为你自有资产，或已获得明确书面授权
- 不用于分发破解他人商业软件、绕过第三方服务认证或未授权访问
- 客户端侧绕过只对本地生效，不代表能突破服务端校验或设备风控

作者不对任何违反当地法律法规的使用方式承担责任。请在合法授权范围内使用。
