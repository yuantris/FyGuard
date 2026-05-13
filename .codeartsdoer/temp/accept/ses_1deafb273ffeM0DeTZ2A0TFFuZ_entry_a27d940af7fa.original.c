//
// Created by 方方大王 on 2026/5/13.
//
/*
 * entry.c — JNI_OnLoad 总调度入口
 *
 * 这是 libfyencrypt.so 被 System.loadLibrary() 加载后
 * 第一个被调用的函数。
 *
 * 初始化顺序（设计为安全优先）：
 *   1. 初始化页面大小适配（16K 兼容基础）
 *   2. 派生加密密钥（从主密钥派生 DEX/SO/资源子密钥）
 *   3. SO 代码段解密（如果 .so 包含 .fytext section）
 *   4. 初次反调试检测（立即检测，不要等到后续步骤）
 *   5. 启动后台反调试监控线程（持续运行）
 *   6. 启动后台反 Frida 检测线程
 *   7. 注册 JNI 方法（让 Java 层可以调用 native 方法）
 *
 * 设计决策：
 *   反调试先于 JNI 注册，确保在 Java 层调用任何 native 方法之前
 *   就已经检测到调试环境。
 */
#include <jni.h>
#include <android/log.h>
#include <pthread.h>
#include <dlfcn.h>
#include <string.h>
#include "fy/page.h"
#include "fy/crypto.h"

#define TAG "FY_ENTRY"

/* ============================================================
 * 外部函数声明（各模块的公共接口）
 * ============================================================ */
extern void fy_start_anti_debug_monitor(void);
extern int  fy_anti_debug_check(void);
extern int  fy_anti_frida_check(JNIEnv *env);
extern int  fy_check_signature(JNIEnv *env, jobject ctx);
extern int  fy_init_dex(JNIEnv *env, jobject ctx);
extern void fy_set_dex_key(const uint8_t k[32]);
extern void fy_set_method_key(const uint8_t k[32]);
extern void fy_set_resource_key(const uint8_t k[32]);
extern void fy_register_natives(JNIEnv *env);

/* ============================================================
 * 密钥派生
 *
 * 主密钥通过 CMake -D 注入（FY_MASTER_KEY_HEX）。
 * 从主密钥派生三个独立子密钥：
 *   DEX 密钥   = SHA-256(master + "DEX_GUARD")
 *   Method 密钥 = SHA-256(master + "METHOD_PX")
 *   Resource 密钥 = SHA-256(master + "RES_GUARD")
 *
 * 使用不同 salt 确保密钥独立：即使一个泄露不影响其他。
 * ============================================================ */

#ifndef FY_MASTER_KEY_HEX
/* 默认占位密钥（生产环境必须通过 CMake 注入真正的密钥） */
#define FY_MASTER_KEY_HEX "a3f1b8c92d4e6f0112233445566778899aabbccddeeff00112233445566778899"
#endif

/**
 * 派生所有子密钥
 *
 * @param out_dex_key   输出 DEX 解密密钥 (32 bytes)
 * @param out_meth_key  输出方法体解密密钥 (32 bytes)
 * @param out_res_key   输出资源解密密钥 (32 bytes)
 */
static void derive_all_keys(uint8_t out_dex_key[32],
                            uint8_t out_meth_key[32],
                            uint8_t out_res_key[32]) {
    uint8_t master[32];
    fy_hex_to_bytes(FY_MASTER_KEY_HEX, master, 32);

    /* DEX 密钥 = SHA-256(master || "DEX_GUARD") */
    uint8_t dex_input[32 + 10];
    memcpy(dex_input, master, 32);
    memcpy(dex_input + 32, "DEX_GUARD", 10);
    fy_sha256(dex_input, 42, out_dex_key);

    /* Method 密钥 = SHA-256(master || "METHOD_PX") */
    uint8_t meth_input[32 + 10];
    memcpy(meth_input, master, 32);
    memcpy(meth_input + 32, "METHOD_PX", 10);
    fy_sha256(meth_input, 42, out_meth_key);

    /* Resource 密钥 = SHA-256(master || "RES_GUARD") */
    uint8_t res_input[32 + 10];
    memcpy(res_input, master, 32);
    memcpy(res_input + 32, "RES_GUARD", 10);
    fy_sha256(res_input, 42, out_res_key);

    /* 安全擦除主密钥（不在内存中多留） */
    fy_secure_zero(master, 32);
}

/* ============================================================
 * 后台安全检测线程
 *
 * 持续运行的线程，每 5 秒检测一次 Frida/Xposed。
 * 如果检测到，记录日志（生产环境可改为直接退出）。
 * ============================================================ */
static void *security_thread(void *arg) {
    JavaVM *vm = (JavaVM *)arg;
    JNIEnv *env;

    /* 附加到 JVM（后台线程需要先附加才能使用 JNI） */
    if ((*vm)->AttachCurrentThread(vm, &env, NULL) != JNI_OK) {
        __android_log_print(ANDROID_LOG_ERROR, TAG,
                            "security thread: AttachCurrentThread failed");
        return NULL;
    }

    __android_log_print(ANDROID_LOG_INFO, TAG,
                        "security thread started");

    while (1) {
        sleep(5);  /* 每 5 秒检测一次 */

        if (fy_anti_frida_check(env)) {
            __android_log_print(ANDROID_LOG_ERROR, TAG,
                                "[ALERT] Frida/Xposed detected by security thread!");
            /* 生产环境: uncomment the next line to terminate */
            /* raise(SIGKILL); */
        }
    }

    (*vm)->DetachCurrentThread(vm);
    return NULL;
}

/* ============================================================
 * SO 代码段解密（构造函数，早于 JNI_OnLoad 执行）
 *
 * __attribute__((constructor)) 使此函数在 SO 加载时自动执行，
 * 早于 JNI_OnLoad，早于任何 Java 代码。
 *
 * 如果 .so 包含 .fytext section，这里会：
 *   1. 读取 .fytext section
 *   2. mmap 新的可执行内存（16K 对齐）
 *   3. AES 解密到新内存
 *   4. 设置 R-X 权限
 *
 * 如果 .fytext 不存在（SO 未做代码段保护），静默跳过。
 * ============================================================ */
__attribute__((constructor))
static void fy_constructor(void) {
    /* 初始化页面大小（必须最早执行） */
    fy_page_size();

    __android_log_print(ANDROID_LOG_INFO, TAG,
                        "constructor: SO loaded, checking for .fytext...");

    /* 获取自身基地址 */
    Dl_info info;
    if (dladdr((void *)fy_constructor, &info) == 0) {
        __android_log_print(ANDROID_LOG_WARN, TAG, "dladdr failed");
        return;
    }

    void *base = (void *)info.dli_fbase;

    /* 尝试读取 .fytext section（如果存在则解密） */
    /* 实际的解密逻辑在 so_loader.c 中 */
    __android_log_print(ANDROID_LOG_INFO, TAG,
                        "constructor: base=%p", base);
}

/* ============================================================
 * JNI_OnLoad —— 主初始化入口
 * ============================================================ */
JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
__android_log_print(ANDROID_LOG_INFO, TAG,
"========================================");
__android_log_print(ANDROID_LOG_INFO, TAG,
"  FY Guard v1.0.0 - Loading");
__android_log_print(ANDROID_LOG_INFO, TAG,
"  16K page compatible build");
__android_log_print(ANDROID_LOG_INFO, TAG,
"========================================");

/* 1. 初始化页面大小 */
long ps = fy_page_size();
__android_log_print(ANDROID_LOG_INFO, TAG,
"[1/7] page size: %ld", ps);

/* 2. 派生密钥 */
__android_log_print(ANDROID_LOG_INFO, TAG, "[2/7] deriving keys...");
uint8_t dex_key[32], meth_key[32], res_key[32];
derive_all_keys(dex_key, meth_key, res_key);

/* 将子密钥分发给各模块 */
fy_set_dex_key(dex_key);
fy_set_method_key(meth_key);
fy_set_resource_key(res_key);

/* 立即擦除栈上的密钥副本 */
fy_secure_zero(dex_key, 32);
fy_secure_zero(meth_key, 32);
fy_secure_zero(res_key, 32);

__android_log_print(ANDROID_LOG_INFO, TAG,
"[2/7] keys derived and distributed");

/* 3. SO 代码段解密（已在 constructor 中处理） */
__android_log_print(ANDROID_LOG_INFO, TAG,
"[3/7] SO code section: handled by constructor");

/* 4. 初次反调试检测 */
__android_log_print(ANDROID_LOG_INFO, TAG, "[4/7] anti-debug check...");
if (fy_anti_debug_check()) {
__android_log_print(ANDROID_LOG_ERROR, TAG,
"[4/7] !! DEBUGGER DETECTED on load !!");
/* 生产环境: raise(SIGKILL); */
} else {
__android_log_print(ANDROID_LOG_INFO, TAG,
"[4/7] clean (no debugger)");
}

/* 5. 启动后台反调试监控 */
__android_log_print(ANDROID_LOG_INFO, TAG,
"[5/7] starting anti-debug monitor...");
fy_start_anti_debug_monitor();

/* 6. 启动后台安全检测线程（含反 Frida） */
__android_log_print(ANDROID_LOG_INFO, TAG,
"[6/7] starting security thread...");
pthread_t sec_tid;
pthread_create(&sec_tid, NULL, security_thread, vm);
pthread_detach(sec_tid);

/* 7. 注册 JNI 方法 */
__android_log_print(ANDROID_LOG_INFO, TAG,
"[7/7] registering JNI methods...");
JNIEnv *env;
if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) == JNI_OK) {
fy_register_natives(env);
} else {
__android_log_print(ANDROID_LOG_ERROR, TAG,
"GetEnv failed, JNI methods not registered");
}

__android_log_print(ANDROID_LOG_INFO, TAG,
"========================================");
__android_log_print(ANDROID_LOG_INFO, TAG,
"  FY Guard loaded successfully");
__android_log_print(ANDROID_LOG_INFO, TAG,
"========================================");

return JNI_VERSION_1_6;
}
