//
// Created by 方方大王 on 2026/5/13.
//
/*
 * integrity.c — APK 完整性校验
 *
 * 防重打包、防篡改、防二次签名。
 *
 * 原理：
 *   构建时，加固工具将 APK 的签名证书 SHA-256 hash 嵌入 assets/integrity.dat。
 *   运行时，native 层从 PackageManager 获取当前 APK 的签名证书，
 *   计算其 SHA-256，与 integrity.dat 中的 hash 比对。
 *   如果不匹配 → APK 被重新签名过 → 退出。
 */
#include <jni.h>
#include <android/log.h>
#include <string.h>
#include "fy/crypto.h"

#define TAG "FY_INTEGRITY"

/**
 * integrity.dat 中嵌入的预期证书 hash
 *
 * 构建时由 HardenTask.embedIntegrity() 从 APK 签名中提取并写入。
 * 运行时通过 read_integrity_dat() 读取。
 */
static uint8_t g_expected_cert_hash[32] = {0};
static int g_integrity_flags = 0;
static int g_integrity_loaded = 0;

/**
 * 从 assets/integrity.dat 读取校验数据
 *
 * 格式: version(4) + flags(4) + cert_sha256(32) = 40 bytes
 */
static int load_integrity_data(JNIEnv *env, jobject context) {
    if (g_integrity_loaded) return 0;

    /* 获取 AssetManager */
    jclass ctx_cls = (*env)->GetObjectClass(env, context);
    jmethodID get_am = (*env)->GetMethodID(env, ctx_cls, "getAssets",
                                           "()Landroid/content/res/AssetManager;");
    jobject am_obj = (*env)->CallObjectMethod(env, context, get_am);
    if (!am_obj) return -1;

    /* 打开 integrity.dat */
    jclass am_cls = (*env)->GetObjectClass(env, am_obj);
    jmethodID open = (*env)->GetMethodID(env, am_cls, "open",
                                         "(Ljava/lang/String;)Ljava/io/InputStream;");
    jstring fname = (*env)->NewStringUTF(env, "integrity.dat");
    jobject is = (*env)->CallObjectMethod(env, am_obj, open, fname);

    if (!is) {
        __android_log_print(ANDROID_LOG_WARN, TAG, "integrity.dat not found");
        (*env)->ExceptionClear(env);
        return -1;
    }

    /* 读取 40 字节 */
    jclass is_cls = (*env)->GetObjectClass(env, is);
    jmethodID read = (*env)->GetMethodID(env, is_cls, "read", "([B)I");
    jbyteArray buf = (*env)->NewByteArray(env, 40);
    jint bytes_read = (*env)->CallIntMethod(env, is, read, buf);

    if (bytes_read < 40) {
        __android_log_print(ANDROID_LOG_ERROR, TAG,
                            "integrity.dat too small: %d bytes", bytes_read);
        return -1;
    }

    /* 解析 */
    jbyte *data = (*env)->GetByteArrayElements(env, buf, NULL);
    int version;
    memcpy(&version, data, 4);
    memcpy(&g_integrity_flags, data + 4, 4);
    memcpy(g_expected_cert_hash, data + 8, 32);

    (*env)->ReleaseByteArrayElements(env, buf, data, JNI_ABORT);
    g_integrity_loaded = 1;

    __android_log_print(ANDROID_LOG_INFO, TAG,
                        "integrity.dat loaded: version=%d flags=0x%02x",
                        version, g_integrity_flags);

    return 0;
}

/**
 * 获取 APK 的签名证书 SHA-256 hash
 *
 * 通过 PackageManager.getPackageInfo() + GET_SIGNING_CERTIFICATES
 * 获取签名证书，然后计算 SHA-256。
 */
static int get_apk_cert_hash(JNIEnv *env, jobject context, uint8_t out_hash[32]) {
    /* context.getPackageManager() */
    jclass ctx_cls = (*env)->GetObjectClass(env, context);
    jmethodID get_pm = (*env)->GetMethodID(env, ctx_cls,
                                           "getPackageManager", "()Landroid/content/pm/PackageManager;");
    jobject pm = (*env)->CallObjectMethod(env, context, get_pm);
    if (!pm) return -1;

    /* context.getPackageName() */
    jmethodID get_pkg = (*env)->GetMethodID(env, ctx_cls,
                                            "getPackageName", "()Ljava/lang/String;");
    jstring pkg = (jstring)(*env)->CallObjectMethod(env, context, get_pkg);

    /* pm.getPackageInfo(pkg, GET_SIGNING_CERTIFICATES) */
    jclass pm_cls = (*env)->GetObjectClass(env, pm);
    jmethodID get_pi = (*env)->GetMethodID(env, pm_cls, "getPackageInfo",
                                           "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    /* PackageManager.GET_SIGNING_CERTIFICATES = 0x08000000 */
    jobject pi = (*env)->CallObjectMethod(env, pm, get_pi, pkg, 0x08000000);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        return -1;
    }

    /* PackageInfo.signingInfo */
    jclass pi_cls = (*env)->GetObjectClass(env, pi);
    jfieldID si_fd = (*env)->GetFieldID(env, pi_cls, "signingInfo",
                                        "Landroid/content/pm/SigningInfo;");
    jobject si = (*env)->GetObjectField(env, pi, si_fd);

    /* SigningInfo.getApkContentsSigners() */
    jclass si_cls = (*env)->GetObjectClass(env, si);
    jmethodID get_sigs = (*env)->GetMethodID(env, si_cls,
                                             "getApkContentsSigners", "()[Landroid/content/pm/Signature;");
    jobjectArray sigs = (jobjectArray)(*env)->CallObjectMethod(env, si, get_sigs);

    if (!sigs || (*env)->GetArrayLength(env, sigs) == 0) {
        return -1;
    }

    /* 取第一个签名证书 */
    jobject sig = (*env)->GetObjectArrayElement(env, sigs, 0);

    /* Signature.toByteArray() */
    jclass sig_cls = (*env)->GetObjectClass(env, sig);
    jmethodID to_bytes = (*env)->GetMethodID(env, sig_cls,
                                             "toByteArray", "()[B");
    jbyteArray cert_bytes = (jbyteArray)(*env)->CallObjectMethod(env, sig, to_bytes);

    /* 计算 SHA-256 */
    jsize len = (*env)->GetArrayLength(env, cert_bytes);
    jbyte *data = (*env)->GetByteArrayElements(env, cert_bytes, NULL);

    fy_sha256((const uint8_t *)data, (size_t)len, out_hash);

    (*env)->ReleaseByteArrayElements(env, cert_bytes, data, JNI_ABORT);

    return 0;
}

/**
 * 校验 APK 签名证书
 *
 * @return 0 签名匹配, -1 不匹配或获取失败
 */
int fy_check_signature(JNIEnv *env, jobject context) {
    /* 加载 integrity.dat */
    if (load_integrity_data(env, context) != 0) {
        __android_log_print(ANDROID_LOG_WARN, TAG,
                            "integrity.dat not loaded, skipping check");
        return 0;  /* 没有 integrity.dat 时跳过检查 */
    }

    /* 检查预期 hash 是否全为 0（未配置时跳过） */
    int all_zero = 1;
    for (int i = 0; i < 32; i++) {
        if (g_expected_cert_hash[i] != 0) {
            all_zero = 0;
            break;
        }
    }
    if (all_zero) return 0;

    /* 获取当前 APK 的签名证书 hash */
    uint8_t current_hash[32];
    if (get_apk_cert_hash(env, context, current_hash) != 0) {
        __android_log_print(ANDROID_LOG_ERROR, TAG,
                            "failed to get APK signing certificate");
        return -1;
    }

    /* 比对 */
    if (memcmp(current_hash, g_expected_cert_hash, 32) != 0) {
        __android_log_print(ANDROID_LOG_ERROR, TAG,
                            "SIGNATURE MISMATCH! APK may be repackaged!");
        __android_log_print(ANDROID_LOG_ERROR, TAG,
                            "expected: %02x%02x%02x%02x...",
                            g_expected_cert_hash[0], g_expected_cert_hash[1],
                            g_expected_cert_hash[2], g_expected_cert_hash[3]);
        __android_log_print(ANDROID_LOG_ERROR, TAG,
                            "current:  %02x%02x%02x%02x...",
                            current_hash[0], current_hash[1],
                            current_hash[2], current_hash[3]);
        return -1;
    }

    __android_log_print(ANDROID_LOG_INFO, TAG,
                        "signature check passed");
    return 0;
}
