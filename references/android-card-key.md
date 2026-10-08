# Android APK 卡密链路

## 一、先判定卡密落在哪一层

| 层 | 判定线索 | 工具 |
|---|---|---|
| Java 层（smali） | jadx 里能直接搜到卡密/校验类名；无 System.loadLibrary | jadx / apktool |
| native 层（so） | `System.loadLibrary("xxx")`；Java 侧方法声明 `native`；校验逻辑在 JNI | IDA / Ghidra / radare2（静态 patch，Xposed 可选） |
| 加固壳 | APK 内 dex 异常小、`libxxxshell.so`、反编译后只有 StubApplication | 先脱壳再回前两层 |
| 纯网络 | Java 层只有请求封装，判定靠服务端返回 | 抓包 / mock |

判定顺序：**能 jadx 出可读代码 → Java 层；Java 侧是 native 方法 → so 层；只有壳桩 → 脱壳**。

## 二、工具链与命令

```bash
# 解包 + 反编译
apktool d target.apk -o work/smali          # smali，可改可回编
jadx -d work/java target.apk                # Java 源码，用于读逻辑

# 特征扫描（本 Skill 脚本）
python scripts/kami_scan.py target.apk --top 15 --json work/scan.json
python scripts/kami_scan.py work/smali --top 30        # 已解包目录

# 定位校验类
grep -rniE "kami|cardkey|cdkey|activate|license|isvip|expire|verify" work/java --include=*.java -l
grep -rniE "kami|cardkey|activate|license|isvip|expire" work/smali -l

# 回编 + 对齐 + 签名（顺序不可颠倒：回编 → 对齐 → 签名）
apktool b work/smali -o work/patched.apk
python ../scripts/zipalign4.py work/patched.apk work/aligned.apk   # 必须！漏了会 -124 装不上
keytool -genkey -v -keystore work/k.keystore -alias k -keyalg RSA -validity 3650 -storepass 123456 -keypass 123456 -dname "CN=k"
apksigner sign --ks work/k.keystore --ks-pass pass:123456 --ks-key-alias k work/aligned.apk
adb install -r work/aligned.apk
```

## 三、Java 层（smali）判定点

典型形态：

```java
public boolean checkCard(String code) {
    String local = hash(code);
    String saved = sp.getString("license", "");
    return local.equals(saved);          // ← 判定点
}
```

对应 smali 判定点通常是：

```
invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
move-result v0
return v0
```

三类改动，代价从低到高：

1. **Xposed / LSPosed Hook（不重打包，可选）**：需 root，用 `scripts/xposed_kami_module.java` 强制返回 true，适合先验证判定点对不对。
2. **smali 分支 patch**：把 `if-eqz v0, :cond_x` 改成 `if-nez`，或改 `goto`。
3. **方法头恒返回**：在方法开头插入 `const/4 v0, 0x1` + `return v0`（用 `scripts/smali_kami_patch.py`）。

```bash
python scripts/smali_kami_patch.py work/smali                 # dry-run 看候选
python scripts/smali_kami_patch.py work/smali --apply --ret true --keywords activate,vip --limit 5
```

注意：
- 改前确认返回类型是 `Z`；返回 `V` 或对象的方法要改**调用点**而非方法体。
- 有 `.locals 0` 时脚本会自动提到 `.locals 1`，避免 `v0` 与 `p0` 冲突。
- 重打包后再签名；若原 APK 有签名校验，需一并处理或改走 Hook 路线。

## 四、native 层（so / shell）

1. 定位导出函数：`JNI_OnLoad` 里 `RegisterNatives` 表是关键，表中给出 Java 方法 ↔ native 函数地址映射。

```bash
readelf -Ws lib/armeabi-v7a/libxxx.so | grep -i "check\|auth\|license\|verify"
r2 -A lib/armeabi-v7a/libxxx.so -c "afl~check"
```

2. 判定点一般在末尾的返回值赋值，常见：
   - ARM：`MOVW R0, #1` / `MOVS R0, #0` → 改 `#0` 为 `#1`
   - 分支：`CMP` 后的 `BEQ/BNE` → 反转或改 `NOP`
3. 动态确认优先于静态猜：

```javascript
// 按导出名
Interceptor.attach(Module.findExportByName("libxxx.so", "Java_com_x_Check"), {...});
// 按偏移：CONFIG.nativeTargets 填 "libxxx.so!0x1a2b3"
```

4. 返回值强制：`retval.replace(ptr(1))`（仅对返回 int/bool 有效；返回结构体或指针不要强改）。

## 五、加固壳

识别：`AndroidManifest.xml` 的 application 指向 `StubApplication/ProxyApplication`；`lib/` 下有 `libjiagu/libdexhelper/libshell` 等；dex 数量异常或体积异常小。

脱壳路径（按代价）：
1. **Xposed 脱壳模块**（如 DumpDex / FDex2 一类）：装上勾选目标 App，运行后到 `/data/data/<pkg>/` 取 dump 出的 dex，代价最低。
2. **反射大师 / 核心破解**等现成工具：一键 dump，适合不想折腾框架的情况。
3. **手工 dump**：`adb shell` 拿到 pid 后读 `/proc/<pid>/maps`，找到 dex 映射区段，用 `dd` 把内存里的 dex 拷出来（需 root）。
4. 改 ROM 类方案仅在前面都失败时考虑。

脱壳后合并 dex → jadx 看逻辑 → 回到第三节。

## 六、网络型卡密

抓到验证域名（如 `https://w.t3yanzheng.com/...`）后：

- **判定归属**：断网启动，若直接拒绝 → C 类（服务端主导）；若可用一段时间 → B 类（本地缓存 token）。
- 三条绕过路径：
  1. 客户端响应 Hook（OkHttp / HttpURLConnection）：改返回体 JSON，把 `status:0` 改 1。
  2. hosts 重定向 + 本地 mock server 复刻响应（需自签证书 + 安装到系统/用户 CA，Android 7+ 注意 network-security-config）。
  3. 直接 patch 本地解析响应后的判定分支（最稳，绕过所有网络校验）。
- mock 服务只在本地起，不向真实第三方服务发请求。

## 七、本地持久化

卡密状态常落在 `SharedPreferences` / 文件 / SQLite：

```bash
adb shell run-as <pkg> cat /data/data/<pkg>/shared_prefs/*.xml
adb shell run-as <pkg> ls -R /data/data/<pkg>/files
```

- 清数据可复位试用：`adb shell pm clear <pkg>`
- 时间型试用：除清数据外，可 smali patch 时间比较逻辑（把"当前时间 > 到期时间"的分支反转），或在 Xposed 模块里 Hook `System.currentTimeMillis` 返回固定值。
