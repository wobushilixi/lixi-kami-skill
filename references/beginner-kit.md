# 新手工具箱：术语、工具、操作顺序、报错对照

## 一、先记住三句话

1. **先观察，后修改**：先用 jadx 看清校验流程，或用 logcat / 抓包看清楚，再动手改。盲改最容易崩。
2. **默认改文件（静态 patch）**：本 Skill 不依赖注入框架，主力手段是 smali / 二进制 patch + 重打包 + 重签。
3. **随时备份**：原文件先 `.bak`，改动只在工作副本上做。

## 二、术语表

| 术语 | 含义 |
|---|---|
| APK / DEX / Smali | 安卓安装包 / 其中的字节码 / 字节码的可读汇编形式（改它就是改程序逻辑） |
| jadx / apktool | 把 APK 反编译成 Java 源码 / 解包成 smali 并可回编的工具 |
| Hook | 拦住某个函数，偷看参数、改返回值（需 Xposed 等框架，本 Skill 里是可选手段） |
| Xposed / LSPosed | 安卓上的 Hook 框架，需要 root，装模块后不用改 APK 就能改函数行为 |
| JNI / so | Java 调用 C/C++ 的桥 / 编译后的原生库（逻辑在 so 里时 smali 改不动） |
| ARM / ARM64 | 手机 CPU 指令集，改 so 要看它 |
| 加固 / 加壳 / 脱壳 | 把真实代码加密藏起来 / 把它还原出来 |
| 重打包 / 重签 | 改完 smali 后重新打成 APK，并**必须重新签名**才能安装 |
| 签名校验 | 程序运行时检查自己的签名是否被换过，换过就拒绝运行 |
| PE / 导入表 / IAT | Windows 可执行文件格式 / 它用到的系统函数清单 / 函数地址表 |
| OEP | 壳解压缩完、真正程序开始的地址（脱壳的关键点） |
| 熵 | 数据的"混乱度"，>7.2 基本意味着压缩或加密 |
| keygen / 注册机 | 还原出卡密算法后写的生成器 |
| 机器码 / HWID | 用硬件信息算出的设备指纹，用来绑定卡密 |
| 心跳 | 客户端定时向服务端报到的续期请求 |
| logcat | 安卓系统日志，用 `adb logcat` 看，能观察程序跑到了哪一步 |
| O1/O2/O3 | 本 Skill 的开源分流：对照开源 / 分析开源 / 产出开源 |
| DevTools | 浏览器自带的开发者工具（F12），看请求、看 JS、看存储 |
| HAR | DevTools 导出的抓包文件，记录了所有请求与响应，可离线分析 |
| Overrides | DevTools 的「本地覆盖」功能，用本地 JS 替换线上 JS |
| 油猴 / Tampermonkey | 浏览器插件，可在页面加载时自动执行你写的脚本 |
| mitmproxy / Charles / Reqable | 代理抓包工具，能拦下并修改请求与响应 |
| localStorage / sessionStorage | 网页在浏览器本地存的数据（会员状态常藏在这） |
| JWT | 一种登录令牌，长得像 `eyJ...`，常用来保存登录/会员状态 |
| WASM | 网页里的二进制模块，核心算法可能藏在里面 |

## 三、工具清单

### Android（不需要 root 也能用的排前面）

| 工具 | 用途 | 备注 |
|---|---|---|
| jadx-gui | 看 Java 源码、搜关键词 | **入门第一件工具** |
| apktool | 解包成 smali、回编 | `apktool d` / `apktool b` |
| MT 管理器 / NP 管理器 | 手机端直接改 smali、一键去签名校验、一键重签 | **新手最省力**，装在手机上就行 |
| uber-apk-signer / apksigner | 签名 | 重打包后必做 |
| adb | 安装、清数据、**看 logcat** | `adb install -r` / `adb logcat` |
| Reqable / 小黄鸟 / Charles | 抓包看验证请求与响应 | 看 `sign`、到期时间字段 |
| 反射大师 / 核心破解 | 加固 App 脱壳、去校验 | 需要框架环境 |
| Xposed / LSPosed | 运行时 Hook（**可选**） | 需要 root；本 Skill 默认不依赖它 |

### Windows

| 工具 | 用途 |
|---|---|
| DIE / PEiD | 查壳、查编译器 |
| x32dbg / x64dbg | 动态调试、下断点（新手主力） |
| IDA / Ghidra / radare2 | 静态反汇编（Ghidra 免费） |
| HxD / 010 Editor | 改二进制字节、全局替换 |
| API Monitor | 看程序调用了哪些系统函数 |
| Process Hacker | 看/杀线程（对付后台校验线程） |
| Cheat Engine | 搜内存里的状态值（试用天数、标志位） |
| dnSpy / ILSpy / de4dot | .NET 程序直读 IL、去混淆 |
| upx | UPX 壳直接 `upx -d` 脱 |

### Web（网页卡密 / 网页验证）

| 工具 | 用途 | 备注 |
|---|---|---|
| Chrome / Edge + DevTools | 看请求（Network）、搜 JS（Sources）、看存储（Application） | **零安装，第一步就用它** |
| Tampermonkey（油猴） | 写脚本改页面判定、改 localStorage | 一次写好长期生效 |
| Reqable / 小黄鸟 / Charles | 手机与网页抓包 | 手机抓包装它的证书 |
| mitmproxy | 命令行代理，用 Python 脚本改请求/响应 | `mitmproxy -s rewrite.py` |
| Proxy SwitchyOmega | 浏览器快速切代理 | 配合 mitmproxy 用 |
| js-beautify / deobfuscate | 把压缩/混淆的 JS 格式化、还原 | JS 全是一行时先用它 |
| node | 语法检查：`node --check x.js` | 改完 JS 必跑 |

## 四、环境准备（照抄即可）

```bash
# 1) 解包 / 回编 / 签名（主力流程，不需要 root）
apktool d target.apk -o work/smali          # 解包
#   ... 用 jadx 看逻辑，改 smali ...
apktool b work/smali -o work/patched.apk    # 回编
java -jar uber-apk-signer.jar --apks work/patched.apk   # 签名（v1+v2+v3 一次搞定）

# 2) 安装与观察
adb uninstall <包名>                        # 签名变了要先卸载旧版
adb install -r work/patched.apk
adb logcat | grep -i "kami\|license\|vip\|error"   # 看程序打到哪一步

# 3) 清本地状态（验证是否真的绕过）
adb shell pm clear <包名>
```

## 五、从 0 到 1 的 12 步

1. 备份原文件（`.bak`），记下 size + SHA256。
2. `python scripts/packer_detect.py <target>` —— 先查壳、签名校验、机器码。
3. 人工复核：能不能直接反编译？重打包会不会被签名校验拦？
4. `python scripts/kami_scan.py <target>` —— 扫卡密特征，看关键词与验证域名。
5. jadx 打开，搜：`kami / license / activate / vip / verify / expire / 卡密 / 激活`。
6. 搜不到就换入口：从输入（getText）或输出（Toast / 错误提示字符串）回溯。
7. **只观察不改**：`adb logcat` + 抓包，看清请求参数和错误提示。
8. 断网 / 联网 / 清数据三态各跑一次 → 定 A/B/C/D 类。
9. 确认判定点，并**枚举同族方法**（isVip 系、getVipLevel、vip 字段赋值）。
10. 出方案（≥2 候选 + 推荐 + 风险），**等确认**。
11. 实施：smali patch / 二进制 patch → 处理签名校验 → 重打包 → 重签。
12. 三态验证，贴真实输出；没跑的写 `未执行`。

### Web 目标请按这 8 步

1. 浏览器打开目标页，F12 → Network，勾 Preserve log。
2. 输入一个错误卡密点提交，找到验证请求，看 URL、参数、响应字段。
3. 响应里有没有 `sign` / `nonce` / `timestamp` —— 有的话改包基本没戏，直接跳到第 5 步。
4. Sources 里 `Ctrl+Shift+F` 全站搜：`kami / card / license / verify / vip / expire / 卡密 / 激活`。
5. 找到前端判定分支（通常是 `if (resp.code === 0)` 之类），决定改哪里。
6. 实施（按代价）：改本地 JS 副本 → DevTools Overrides → 油猴脚本 → mitmproxy 改响应。
7. `node --check` 校验语法；刷新看 console 有没有你的日志（确认脚本真被执行了）。
8. 三态实测：断网（DevTools 勾 Offline）、联网、清 localStorage + cookie 各跑一遍。

## 六、常见报错对照

| 现象 | 原因 | 处理 |
|---|---|---|
| 装上弹"验签失败 / 参数错误" | 签名自校验 | `references/anti-defense.md` 第一节 |
| 装上直接闪退 | smali 语法错 / 寄存器冲突 / 完整性校验 | 检查 `.locals` 是否够用；patch 掉完整性校验 |
| `INSTALL_FAILED_UPDATE_INCOMPATIBLE` | 签名与已装版本不同 | `adb uninstall <包名>` 再装 |
| `INSTALL_PARSE_FAILED_NO_CERTIFICATES` | 没签名 | 用 uber-apk-signer 重签 |
| apktool 回编报错 | 资源或框架问题 | `apktool b -r`（不编资源）或装对应 framework |
| jadx 打开全是 a/b/c 乱码类名 | 代码混淆 | 按调用链跟；或用 `smali_kami_patch.py` 按关键词找 |
| jadx 只看到壳外壳，没有业务代码 | 被加固 | 先脱壳（反射大师 / Xposed 脱壳模块） |
| 改了 isVip 界面仍显示未激活 | 还有别的判定点 | 枚举同族方法一起改 |
| 抓包看不到请求 | 不走代理 / 证书未信任 | Reqable 用本机或 VPN 模式；Android 7+ 需装系统证书 |
| 改了响应却没生效 | 响应带服务端签名 | 放弃改包，改客户端判定点 |
| 调试器一附加程序就退出 | 反调试 | 走静态 patch；或先 patch 掉反调试 |
| 改了 JS 刷新又变回去 | 没用 Overrides 或走了缓存 | 用 DevTools Overrides；勾 Disable cache |
| 网页状态改了过一会又掉 | 心跳请求被服务端纠正 | 同时拦心跳响应或改本地时间判断 |
| 网页 JS 全是 `_0x` 乱码 | 代码混淆 | 先 js-beautify 格式化；读不懂就直接改渲染后的状态 |
| HTTPS 抓不到包 | 证书没装 | 装 mitmproxy / Charles 根证书并信任 |
| 改了接口响应没生效 | 响应带签名，前端验签 | 放弃改包，改前端判定分支 |
| 网页里搜不到卡密关键词 | 逻辑在 WASM 或异步加载的 JS | 查 `.wasm` 文件；Network 里找后加载的 JS |

## 七、新手最常犯的三个错

1. **上来就改文件**：不知道有没有壳、有没有签名校验，改完要么没效果要么闪退。
2. **只改一个判定点**：会员状态通常由多个方法共同决定，必须一起改。
3. **只在一种状态下验证**：断网能用不代表联网能用，必须三态都测。
