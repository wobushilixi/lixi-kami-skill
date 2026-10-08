/**
 * xposed_kami_module.java - 卡密判定点 Hook 模板（Xposed / LSPosed）
 *
 * 仅当设备已 root 并装了 LSPosed / Xposed 时使用。
 * 本 Skill 默认走静态 smali patch 路线，此模块是「可选增强」：
 * 用来在不改文件的前提下验证判定点是否正确，确认后再落盘 patch。
 *
 * 使用步骤：
 *   1. Android Studio 新建 Empty Activity 工程，把本文件放进去
 *   2. 在 app/build.gradle 加：compileOnly 'de.robv.android.xposed:api:82'
 *   3. 新建 assets/xposed_init，内容写：com.kami.hook.KamiHook
 *   4. AndroidManifest.xml 的 <application> 内加三个 meta-data：
 *        xposedmodule      = true
 *        xposeddescription = 卡密判定点 Hook
 *        xposedminversion  = 82
 *   5. 编译安装 → LSPosed 里勾选目标应用 → 重启目标应用
 *   6. 看 logcat：adb logcat -s KamiHook
 */

package com.kami.hook;

import android.content.pm.Signature;
import android.os.Build;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class KamiHook implements IXposedHookLoadPackage {

    // ============================== CONFIG ==============================
    private static final String TARGET_PACKAGE = "com.example.target";

    /** true = 强制返回 FORCE_VALUE；false = 只打印日志，不改行为（先用这个观察） */
    private static final boolean FORCE_RETURN = false;
    private static final boolean FORCE_VALUE = true;

    /** 方法名命中任意一个即 Hook（小写比较） */
    private static final String[] METHOD_PATTERNS = {
            "isvip", "ispro", "ismember", "isactive", "isvalid", "isexpired",
            "islicensed", "checkauth", "checklicense", "checkkey", "checkcard",
            "verifykey", "isvipexpired", "isvipstate", "getviplevel", "kami"
    };

    /** 顺手处理：绕过签名校验用的伪造值（先用观察模式拿到真实值再填） */
    private static final boolean BYPASS_SIGNATURE = false;
    private static final int FAKE_SIGN_HASHCODE = 0;      // 例如 -1234567890
    private static final String FAKE_SIGN_CHARS = "";     // Signature.toCharsString() 的真实值

    /** 固定机器码（应对卡密绑设备） */
    private static final boolean FAKE_DEVICE = false;
    private static final String FAKE_SERIAL = "ABCDEF0123456789";
    private static final String FAKE_ANDROID_ID = "0123456789abcdef";
    private static final String FAKE_IMEI = "860000000000000";

    private static final boolean ANTI_DEBUG = true;
    // =====================================================================

    private static final String TAG = "KamiHook";

    private static boolean hit(String name, String[] patterns) {
        String low = name.toLowerCase();
        for (String p : patterns) {
            if (low.contains(p)) return true;
        }
        return false;
    }

    private static void log(String msg) {
        XposedBridge.log(TAG + ": " + msg);
    }

    @Override
    public void handleLoadPackage(final XC_LoadPackage.LoadPackageParam lpparam) {
        if (!TARGET_PACKAGE.equals(lpparam.packageName)) return;
        log("attached -> " + lpparam.packageName);

        if (ANTI_DEBUG) hookAntiDebug(lpparam);
        if (BYPASS_SIGNATURE) hookSignature(lpparam);
        if (FAKE_DEVICE) hookDevice(lpparam);

        // 通用做法：拦住类加载，对目标包内的每个类做方法名匹配后 Hook
        XposedHelpers.findAndHookMethod(ClassLoader.class, "loadClass", String.class,
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        Object result = param.getResult();
                        if (!(result instanceof Class)) return;
                        Class<?> cls = (Class<?>) result;
                        String cn = cls.getName();
                        if (!cn.startsWith(TARGET_PACKAGE)) return;
                        tryHookClass(cls);
                    }
                });
    }

    private void tryHookClass(Class<?> cls) {
        Method[] methods;
        try {
            methods = cls.getDeclaredMethods();
        } catch (Throwable t) {
            return;
        }
        for (Method m : methods) {
            if (Modifier.isAbstract(m.getModifiers())) continue;
            if (!hit(m.getName(), METHOD_PATTERNS)) continue;
            try {
                Object[] typesAndCb = buildParams(m);
                XposedHelpers.findAndHookMethod(cls, m.getName(), typesAndCb);
            } catch (Throwable t) {
                // 已 hook 过或签名不兼容，跳过
            }
        }
    }

    /** 组装 XposedHelpers.findAndHookMethod 的变长参数 */
    private Object[] buildParams(final Method m) {
        Class<?>[] ptypes = m.getParameterTypes();
        Object[] args = new Object[ptypes.length + 1];
        System.arraycopy(ptypes, 0, args, 0, ptypes.length);
        args[ptypes.length] = new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                Object ret = param.getResult();
                log(m.getDeclaringClass().getSimpleName() + "." + m.getName()
                        + "() = " + ret);
                if (!FORCE_RETURN) return;
                if (ret instanceof Boolean) {
                    param.setResult(FORCE_VALUE);
                    log("  -> forced " + FORCE_VALUE);
                } else if (ret instanceof Integer) {
                    param.setResult(FORCE_VALUE ? 1 : 0);
                    log("  -> forced " + (FORCE_VALUE ? 1 : 0));
                }
            }
        };
        return args;
    }

    private void hookAntiDebug(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            XposedHelpers.findAndHookMethod("android.os.Debug", lpparam.classLoader,
                    "isDebuggerConnected", new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            param.setResult(false);
                        }
                    });
            log("anti-debug installed");
        } catch (Throwable t) {
            log("anti-debug failed: " + t);
        }
    }

    private void hookSignature(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            final Class<?> sig = XposedHelpers.findClass(Signature.class.getName(),
                    lpparam.classLoader);
            if (FAKE_SIGN_HASHCODE != 0) {
                XposedHelpers.findAndHookMethod(sig, "hashCode", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        param.setResult(FAKE_SIGN_HASHCODE);
                    }
                });
            }
            if (!FAKE_SIGN_CHARS.isEmpty()) {
                XposedHelpers.findAndHookMethod(sig, "toCharsString", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        param.setResult(FAKE_SIGN_CHARS);
                    }
                });
            }
            log("signature bypass installed");
        } catch (Throwable t) {
            log("signature hook failed: " + t);
        }
    }

    private void hookDevice(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            XposedHelpers.setStaticObjectField(Build.class, "SERIAL", FAKE_SERIAL);
            XposedHelpers.findAndHookMethod("android.os.Build", lpparam.classLoader,
                    "getSerial", new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            param.setResult(FAKE_SERIAL);
                        }
                    });
            XposedHelpers.findAndHookMethod("android.provider.Settings$Secure",
                    lpparam.classLoader, "getString",
                    android.content.ContentResolver.class, String.class,
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            if ("android_id".equals(param.args[1])) {
                                param.setResult(FAKE_ANDROID_ID);
                            }
                        }
                    });
            XposedHelpers.findAndHookMethod("android.telephony.TelephonyManager",
                    lpparam.classLoader, "getDeviceId", new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            param.setResult(FAKE_IMEI);
                        }
                    });
            log("device faking installed");
        } catch (Throwable t) {
            log("device hook failed: " + t);
        }
    }
}
