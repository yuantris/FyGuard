//
// Created by 方方大王 on 2026/5/13.
//
/*
 * jni_bridge.c — JNI 方法注册
 *
 * 将 native 方法绑定到 Java 类 com.fy.guard_stub.NativeLoader。
 * 使用 RegisterNatives 动态注册（而非 JNI 命名约定静态注册）。
 *
 * 动态注册的好处：
 *   1. 不需要遵守 JNI 命名规则（函数名可以任意）
 *   2. 符号可以被 strip（增加逆向难度）
 *   3. 注册失败时有明确的错误信息
 *   4. 可以在运行时动态选择实现
 */
#include <jni.h>
#include <android/log.h>
#include <string.h>
#include "fy/page.h"
#include "fy/crypto.h"

#define TAG "FY_JNI"

/* ============================================================
 * 外部函数声明
 * ============================================================ */
extern int  fy_init_dex(JNIEnv *env, jobject ctx);
extern int  fy_init_methods(JNIEnv *env, jobject ctx);
extern int  fy_check_signature(JNIEnv *env, jobject ctx);
extern int  fy_anti_debug_check(void);
extern int  fy_anti_frida_check(JNIEnv *env);
extern long fy_page_size(void);

/* ============================================================
 * JNI 方法实现
 * ============================================================ */

/**
 * NativeLoader.nativeInit(Context)
 *
 * 在 StubApplication.attachBaseContext 中调用。
 * 完成所有剩余的初始化工作：
 *   1. 签名完整性校验
 *   2. DEX 解密加载
 *   3. 方法体还原引擎初始化
 *   4. 最终反调试/反 Frida 检查
 */
static void nativeInit(JNIEnv *env, jclass clazz, jobject context) {
    __android_log_print(ANDROID_LOG_INFO, TAG, "nativeInit called");

    /* 1. 签名校验 */
    int sig_result = fy_check_signature(env, context);
    if (sig_result != 0) {
        __android_log_print(ANDROID_LOG_ERROR, TAG,
                            "signature check FAILED (%d)", sig_result);
        /* 生产环境: 可以直接退出 */
    }

    /* 2. DEX 解密加载 */
    int dex_result = fy_init_dex(env, context);
    if (dex_result != 0) {
        __android_log_print(ANDROID_LOG_ERROR, TAG,
                            "DEX loading FAILED (%d)", dex_result);
        return;
    }

    /* 3. 方法体还原初始化（如果有 enc_methods.bin） */
    fy_init_methods(env, context);

    /* 4. 最终安全检查 */
    if (fy_anti_debug_check()) {
        __android_log_print(ANDROID_LOG_ERROR, TAG,
                            "debugger detected during init!");
    }
    if (fy_anti_frida_check(env)) {
        __android_log_print(ANDROID_LOG_ERROR, TAG,
                            "Frida/Xposed detected during init!");
    }

    __android_log_print(ANDROID_LOG_INFO, TAG,
                        "nativeInit complete");
}

/**
 * NativeLoader.nativeGetPageInfo()
 *
 * 返回页面大小信息（调试用）。
 */
static jstring nativeGetPageInfo(JNIEnv *env, jclass clazz) {
    long ps = fy_page_size();
    char buf[128];
    snprintf(buf, sizeof(buf),
             "pageSize=%ld, maxPageAlign=16384, mmapExec=true", ps);
    return (*env)->NewStringUTF(env, buf);
}

/**
 * NativeLoader.nativeSecurityCheck(Context)
 *
 * 综合安全检查。
 * @return 0=安全, 1=被调试, 2=Frida, 3=签名失败
 */
static jint nativeSecurityCheck(JNIEnv *env, jclass clazz, jobject context) {
    if (fy_anti_debug_check())           return 1;
    if (fy_anti_frida_check(env))        return 2;
    if (fy_check_signature(env, context)) return 3;
    return 0;
}

/* ============================================================
 * JNI 方法注册表
 *
 * 格式: {Java方法名, Java方法签名, C函数指针}
 *
 * 方法签名说明:
 *   (Landroid/content/Context;)V  →  参数: Context, 返回: void
 *   ()Ljava/lang/String;          →  参数: 无, 返回: String
 *   (Landroid/content/Context;)I  →  参数: Context, 返回: int
 * ============================================================ */
static const JNINativeMethod g_methods[] = {
        {
                "nativeInit",                           // Java 方法名
                "(Landroid/content/Context;)V",         // 方法签名
                (void *)nativeInit                      // C 函数指针
        },
        {
                "nativeGetPageInfo",
                "()Ljava/lang/String;",
                (void *)nativeGetPageInfo
        },
        {
                "nativeSecurityCheck",
                "(Landroid/content/Context;)I",
                (void *)nativeSecurityCheck
        }
};

static int g_registered = 0;

/**
 * 注册所有 JNI 方法
 * 在 JNI_OnLoad 中调用
 */
void fy_register_natives(JNIEnv *env) {
    if (g_registered) return;

    /* 查找目标 Java 类 */
    jclass cls = (*env)->FindClass(env, "com/fy/guard_stub/NativeLoader");
    if (!cls) {
        __android_log_print(ANDROID_LOG_ERROR, TAG,
                            "NativeLoader class not found!");
        (*env)->ExceptionClear(env);
        return;
    }

    /* 注册 */
    int count = sizeof(g_methods) / sizeof(g_methods[0]);
    jint result = (*env)->RegisterNatives(env, cls, g_methods, count);

    if (result < 0) {
        __android_log_print(ANDROID_LOG_ERROR, TAG,
                            "RegisterNatives failed!");
        (*env)->ExceptionClear(env);
        return;
    }

    g_registered = 1;
    __android_log_print(ANDROID_LOG_INFO, TAG,
                        "registered %d native methods", count);
}
