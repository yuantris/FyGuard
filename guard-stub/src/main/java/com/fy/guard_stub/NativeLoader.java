package com.fy.guard_stub;

import android.content.Context;

/**
 * NativeLoader — JNI 桥接类
 *
 * 连接 Java 壳层和 Native 保护层。
 *
 * 职责：
 *   1. 在 static 块中 System.loadLibrary("fyencrypt") 加载 native 库
 *      → 触发 JNI_OnLoad（初始化反调试、密钥派生、SO 解密等）
 *   2. 持有 sClassLoader 静态字段，由 native 层设置
 *      → StubApplication 读取此字段来加载真实 DEX
 *   3. 提供 nativeInit / nativeSecurityCheck 等 JNI 方法
 *
 * 所有 native 方法通过 RegisterNatives 动态注册（非静态命名规则），
 * 所以方法名不需要与 C 函数名对应。
 * 但为了可读性，这里保持了有意义的命名。
 *
 * 注意：
 *   这个类的完整类名 com.fy.guard_stub.NativeLoader 在以下位置被引用：
 *   - CMakeLists.txt 中的 JNI RegisterNatives 查找
 *   - dex_guard.c 中设置 sClassLoader 字段
 *   修改类名时必须同步修改 native 代码。
 */
public class NativeLoader {

    /**
     * 自定义 ClassLoader
     *
     * 由 native 层的 dex_guard.c 在解密 DEX 并创建 ClassLoader 后设置。
     * StubApplication.attachBaseContext 读取此字段来加载真实 Application 类。
     *
     * 声明为 public static volatile 确保多线程可见性。
     */
    public static volatile ClassLoader sClassLoader;

    /**
     * 加载 native 库
     *
     * 这个 static 块在类首次被引用时执行。
     * StubApplication.attachBaseContext 中调用 NativeLoader 的任何方法
     * 都会触发此处的 loadLibrary。
     *
     * 加载 libfyencrypt.so 会触发：
     *   1. __attribute__((constructor)) 函数（SO 代码段解密）
     *   2. JNI_OnLoad（密钥派生、反调试初始化、JNI 注册）
     */
    static {
        System.loadLibrary("fyencrypt");
    }

    /**
     * Native 安全初始化
     *
     * 在 StubApplication.attachBaseContext 中调用。
     * native 层完成：
     *   1. APK 签名完整性校验
     *   2. DEX 解密 + ClassLoader 创建
     *   3. 方法体还原引擎初始化（如果有 enc_methods.bin）
     *   4. 最终反调试/反 Frida 检查
     *
     * @param context Application context
     */
    public static native void nativeInit(Context context);

    /**
     * 获取页面大小信息
     *
     * 调试用，返回当前系统的页面大小和兼容性信息。
     *
     * @return 例如 "pageSize=16384, maxPageAlign=16384, mmapExec=true"
     */
    public static native String nativeGetPageInfo();

    /**
     * 综合安全检查
     *
     * 可在 App 运行期间周期性调用，持续检测环境安全性。
     *
     * @param context Application context
     * @return 安全状态码:
     *         0 - 安全
     *         1 - 检测到调试器
     *         2 - 检测到 Frida / Xposed
     *         3 - APK 签名校验失败（可能被重打包）
     */
    public static native int nativeSecurityCheck(Context context);
}
