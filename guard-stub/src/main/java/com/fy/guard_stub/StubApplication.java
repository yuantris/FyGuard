package com.fy.guard_stub;

import android.app.Application;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.util.Log;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

/**
 * StubApplication — 加固壳入口
 *
 * 这是加固后 APK 的 Application 类。
 * Gradle 插件会自动将 AndroidManifest.xml 中的
 * android:name 从用户的原始 Application 替换为此类。
 *
 * 用户的真实 Application 类名保存在 meta-data 中：
 *   <meta-data
 *       android:name="com.fy.guard_stub.real_app_class"
 *       android:value="com.example.myapp.MyApplication" />
 *
 * ============================
 * 生命周期代理架构
 * ============================
 *
 * 普通 App 启动流程：
 *   Application.attachBaseContext()
 *   → Application.onCreate()
 *   → Activity.onCreate()
 *
 * 加固后 App 启动流程：
 *   StubApplication.attachBaseContext()
 *   → System.loadLibrary("fyencrypt")        ← 触发 native 初始化
 *   → NativeLoader.nativeInit(this)           ← 解密 DEX + 安全检查
 *   → 创建自定义 ClassLoader                  ← 加载解密后的 DEX
 *   → 替换 LoadedApk.mClassLoader             ← ContentProvider 也能正确加载
 *   → 加载真实 Application 类并实例化
 *   → 注入 Context 到真实 Application
 *   → 替换 ActivityThread.mInitialApplication ← 确保系统使用真实 App
 *   StubApplication.onCreate()
 *   → 真实 Application.onCreate()             ← 委托
 *   → Activity.onCreate()                     ← 从解密 DEX 中加载
 *
 * ============================
 * ClassLoader 替换的必要性
 * ============================
 *
 * ContentProvider 在 Application.onCreate() 之前初始化。
 * 如果不替换 LoadedApk.mClassLoader，ContentProvider 的类
 * 将从原始的 stub DEX（只有壳代码）中查找，找不到真实实现。
 *
 * 替换 ClassLoader 为 DelegateClassLoader（优先查解密 DEX）后，
 * ContentProvider、BroadcastReceiver 等所有组件都能正确加载。
 */
public class StubApplication extends Application {

    private static final String TAG = "FY_STUB";

    /**
     * meta-data key：保存用户真实 Application 类名
     * 与 ManifestProcessor.META_REAL_APP 保持一致
     */
    private static final String META_REAL_APP_CLASS = "com.fy.guard_stub.real_app_class";

    /** 用户的真实 Application 实例 */
    private Application realApp;

    /** 初始化是否成功 */
    private boolean initialized;

    // ================================================================
    // 生命周期：attachBaseContext（核心初始化逻辑）
    // ================================================================

    @Override
    protected void attachBaseContext(Context base) {
        Log.i(TAG, "attachBaseContext: starting early init BEFORE super...");

        try {
            // ==========================================================
            // ⚠️ 关键修复：在 super.attachBaseContext() 之前完成所有初始化！
            //
            // Android 系统在 super.attachBaseContext() 执行过程中
            // 就会初始化 ContentProvider（包括 androidx.startup.InitializationProvider）。
            // 如果此时 ClassLoader 还没替换，ContentProvider 就找不到自己的类。
            //
            // 所以必须在 super 之前完成：
            //   1. 加载 native 库
            //   2. 解密 DEX
            //   3. 创建自定义 ClassLoader
            //   4. 替换 LoadedApk.mClassLoader
            // ==========================================================

            // Step 1: 加载 Native 库
            Log.i(TAG, "  [1/6] loading native library...");
            NativeLoader.loadNativeLibrary();
            Log.i(TAG, "  [1/6] native library loaded");

            // Step 2: Native 安全初始化（解密 DEX，创建 ClassLoader）
            Log.i(TAG, "  [2/6] native security init (DEX decryption)...");
            NativeLoader.nativeInit(base);
            Log.i(TAG, "  [2/6] native init complete");

            // Step 3: 获取自定义 ClassLoader
            Log.i(TAG, "  [3/6] getting custom ClassLoader...");
            ClassLoader customClassLoader = NativeLoader.sClassLoader;

            if (customClassLoader == null) {
                Log.e(TAG, "  [3/6] FATAL: sClassLoader is null!");
            } else {
                Log.i(TAG, "  [3/6] ClassLoader: " + customClassLoader.getClass().getName());
                
                // 设置解密后 DEX 中 NativeLoader 的 sStubClassLoader
                try {
                    Class<?> nlInDex = Class.forName("com.fy.guard_stub.NativeLoader", false, customClassLoader);
                    java.lang.reflect.Field stubCLField = nlInDex.getField("sStubClassLoader");
                    stubCLField.set(null, NativeLoader.sStubClassLoader);
                    Log.i(TAG, "  [3/6] sStubClassLoader set in decrypted DEX: " + NativeLoader.sStubClassLoader);
                } catch (Exception e) {
                    Log.w(TAG, "  [3/6] failed to set sStubClassLoader: " + e.getMessage());
                }
            }

            // Step 4: ⚠️ 关键：在 super 之前替换 ClassLoader！
            // 此时 ContentProvider 即将被初始化，必须让它们能加载到解密后的类
            if (customClassLoader != null) {
                Log.i(TAG, "  [4/6] replacing ClassLoader BEFORE super...");
                replaceClassLoader(base, customClassLoader);
                Log.i(TAG, "  [4/6] ClassLoader replaced BEFORE super");
            }

            // Step 5: 继续执行正常的 attachBaseContext
            // 此时 ContentProvider 初始化时就能找到 androidx.startup.InitializationProvider 了
            Log.i(TAG, "  [5/6] calling super.attachBaseContext()...");
            super.attachBaseContext(base);
            Log.i(TAG, "  [5/6] super.attachBaseContext() complete");

            // ==========================================================
            // super 之后的初始化（可以在 onCreate 中做的，这里也可以继续）
            // ==========================================================

            // Step 6: 从 meta-data 读取真实 Application 类名
            Log.i(TAG, "  [6/6] reading real application class...");
            String realClassName = getRealApplicationClass(base);

            if (realClassName == null || realClassName.isEmpty()) {
                Log.w(TAG, "  [6/6] no real application class configured");
                Log.w(TAG, "  [6/6] app will run with StubApplication only");
                initialized = true;
                return;
            }
            Log.i(TAG, "  [6/6] real application: " + realClassName);

            // Step 7: 加载并实例化真实 Application
            Log.i(TAG, "  [7/7] loading real application...");
            Class<?> realClass = customClassLoader.loadClass(realClassName);
            realApp = (Application) realClass.newInstance();

            // 注入 Context
            injectBaseContext(realApp, base);
            injectLoadedApk(realApp, base);

            // 替换 ActivityThread.mInitialApplication
            replaceInitialApplication(realApp);

            initialized = true;
            Log.i(TAG, "========================================");
            Log.i(TAG, "  Hardening complete: " + realClassName);
            Log.i(TAG, "========================================");

        } catch (Exception e) {
            Log.e(TAG, "Hardening FAILED", e);
            // 初始化失败时，仍调用 super 让 App 以 stub 模式运行
            super.attachBaseContext(base);
        }
    }

    // ================================================================
    // 生命周期委托（全部转发给真实 Application）
    // ================================================================

    @Override
    public void onCreate() {
        super.onCreate();
        if (initialized && realApp != null) {
            Log.i(TAG, "onCreate: delegating to real application");
            realApp.onCreate();
        }
    }

    @Override
    public void onTerminate() {
        super.onTerminate();
        if (realApp != null) {
            realApp.onTerminate();
        }
    }

    @Override
    public void onConfigurationChanged(android.content.res.Configuration newConfig) {
        super.onConfigurationChanged(newConfig);
        if (realApp != null) {
            realApp.onConfigurationChanged(newConfig);
        }
    }

    @Override
    public void onLowMemory() {
        super.onLowMemory();
        if (realApp != null) {
            realApp.onLowMemory();
        }
    }

    @Override
    public void onTrimMemory(int level) {
        super.onTrimMemory(level);
        if (realApp != null) {
            realApp.onTrimMemory(level);
        }
    }

    // ================================================================
    // 内部工具方法
    // ================================================================

    /**
     * 从 AndroidManifest.xml 的 meta-data 中读取真实 Application 类名
     *
     * 对应 ManifestProcessor 写入的：
     *   <meta-data
     *       android:name="com.fy.guard_stub.real_app_class"
     *       android:value="com.example.myapp.MyApplication" />
     *
     * @param context Application context
     * @return 真实 Application 的全限定类名，未配置返回 null
     */
    private String getRealApplicationClass(Context context) {
        try {
            PackageManager pm = context.getPackageManager();
            ApplicationInfo ai = pm.getApplicationInfo(
                    context.getPackageName(),
                    PackageManager.GET_META_DATA
            );
            Bundle metaData = ai.metaData;
            if (metaData != null) {
                return metaData.getString(META_REAL_APP_CLASS);
            }
        } catch (PackageManager.NameNotFoundException e) {
            Log.e(TAG, "failed to read ApplicationInfo", e);
        }
        return null;
    }

    /**
     * 替换 LoadedApk.mClassLoader
     *
     * 通过反射访问 android.app.ContextImpl.mPackageInfo（LoadedApk 类型），
     * 然后替换其 mClassLoader 字段为 DelegateClassLoader。
     *
     * DelegateClassLoader 的查找策略：
     *   1. 先从解密 DEX 的 ClassLoader 查找（primary）
     *   2. 找不到时从原始 stub DEX 的 ClassLoader 查找（fallback）
     *
     * @param base      Context（实际类型是 ContextImpl）
     * @param customCL  解密 DEX 的 ClassLoader
     */
    private void replaceClassLoader(Context base, ClassLoader customCL) throws Exception {
        // ContextImpl.mPackageInfo (LoadedApk)
        Class<?> contextImplClass = Class.forName("android.app.ContextImpl");
        Field packageInfoField = contextImplClass.getDeclaredField("mPackageInfo");
        packageInfoField.setAccessible(true);
        Object loadedApk = packageInfoField.get(base);

        // LoadedApk.mClassLoader
        Class<?> loadedApkClass = loadedApk.getClass();
        Field classLoaderField = loadedApkClass.getDeclaredField("mClassLoader");
        classLoaderField.setAccessible(true);

        ClassLoader originalClassLoader = (ClassLoader) classLoaderField.get(loadedApk);

        // 创建委托 ClassLoader
        ClassLoader delegateClassLoader = new DelegateClassLoader(
                customCL, originalClassLoader
        );

        // 替换
        classLoaderField.set(loadedApk, delegateClassLoader);

        Log.i(TAG, "  ClassLoader replaced: " + delegateClassLoader.getClass().getName());
    }

    /**
     * 注入 Context.mBase 到真实 Application
     *
     * Application.mBase 是 ContextWrapper 的字段，
     * 类型为 ContextImpl，提供实际的 Context 功能。
     * 不注入的话，真实 Application 调用 getResources() 等方法会 NPE。
     */
    private void injectBaseContext(Application app, Context base) throws Exception {
        // ContextWrapper.mBase (Context 类型)
        Field mBaseField = Application.class.getSuperclass()   // Application → ContextWrapper
                .getDeclaredField("mBase");
        mBaseField.setAccessible(true);
        mBaseField.set(app, base);
    }

    /**
     * 注入 Application.mLoadedApk
     *
     * mLoadedApk 是 Application 的字段，类型为 LoadedApk。
     * 系统通过它获取包信息、资源、ClassLoader 等。
     * 不注入的话，某些系统 API 调用会失败。
     */
    private void injectLoadedApk(Application app, Context base) throws Exception {
        // 从 ContextImpl 获取 LoadedApk
        Class<?> contextImplClass = Class.forName("android.app.ContextImpl");
        Field packageInfoField = contextImplClass.getDeclaredField("mPackageInfo");
        packageInfoField.setAccessible(true);
        Object loadedApk = packageInfoField.get(base);

        // Application.mLoadedApk
        Field loadedApkField = Application.class.getDeclaredField("mLoadedApk");
        loadedApkField.setAccessible(true);
        loadedApkField.set(app, loadedApk);
    }

    /**
     * 替换 ActivityThread.mInitialApplication
     *
     * ActivityThread 是 Android 应用的主线程管理类。
     * mInitialApplication 字段持有当前进程的 Application 实例。
     * 替换后，系统的所有 Application 回调都会路由到真实 Application。
     */
    private void replaceInitialApplication(Application newApp) throws Exception {
        // ActivityThread.currentActivityThread()
        Class<?> activityThreadClass = Class.forName("android.app.ActivityThread");
        Method currentMethod = activityThreadClass.getDeclaredMethod("currentActivityThread");
        currentMethod.setAccessible(true);
        Object activityThread = currentMethod.invoke(null);

        if (activityThread == null) {
            Log.w(TAG, "  currentActivityThread returned null (pre-attach?)");
            return;
        }

        // ActivityThread.mInitialApplication
        Field initialAppField = activityThreadClass.getDeclaredField("mInitialApplication");
        initialAppField.setAccessible(true);
        initialAppField.set(activityThread, newApp);
    }

    // ================================================================
    // 委托 ClassLoader
    // ================================================================

    /**
     * DelegateClassLoader — 委托 ClassLoader
     *
     * 实现双 ClassLoader 委托策略：
     *   1. 先从 primary（解密 DEX 的 ClassLoader）查找
     *   2. 找不到时从 fallback（原始 stub DEX 的 ClassLoader）查找
     *
     * 这确保：
     *   - 用户的真实代码（Activity, Service 等）从解密 DEX 加载
     *   - 壳代码（StubApplication 等）从 stub DEX 加载
     *   - Android Framework 类从 BootClassLoader 加载（通过 parent）
     *
     * 同时重写 findLibrary，确保 JNI 库也能正确找到。
     */
    private static class DelegateClassLoader extends ClassLoader {

        /** 解密 DEX 的 ClassLoader（优先） */
        private final ClassLoader primary;

        /** 原始 stub DEX 的 ClassLoader（回退） */
        private final ClassLoader fallback;

        /**
         * @param primary  解密 DEX 的 ClassLoader
         * @param fallback 原始 stub DEX 的 ClassLoader
         */
        DelegateClassLoader(ClassLoader primary, ClassLoader fallback) {
            // parent 设为 fallback 的 parent（通常是 BootClassLoader）
            // 这确保 Android Framework 类（java.lang.*, android.*）能正常加载
            super(fallback.getParent());
            this.primary = primary;
            this.fallback = fallback;
        }

        @Override
        protected Class<?> findClass(String name) throws ClassNotFoundException {
            try {
                // 先从解密 DEX 查找（用户的 Activity, Service 等）
                return primary.loadClass(name);
            } catch (ClassNotFoundException e) {
                // 找不到时从 stub DEX 查找（壳代码）
                return fallback.loadClass(name);
            }
        }

        @Override
        public String findLibrary(String name) {
            String lib = invokeFindLibrary(primary, name);
            if (lib != null) {
                return lib;
            }
            return invokeFindLibrary(fallback, name);
        }

        private static String invokeFindLibrary(ClassLoader cl, String name) {
            try {
                java.lang.reflect.Method m = ClassLoader.class.getDeclaredMethod("findLibrary", String.class);
                m.setAccessible(true);
                return (String) m.invoke(cl, name);
            } catch (Exception e) {
                return null;
            }
        }
    }
}
