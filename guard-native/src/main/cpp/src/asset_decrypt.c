//
// Created by 方方大王 on 2026/5/13.
//
/*
 * asset_decrypt.c — 运行时资源按需解密
 *
 * 与 buildSrc ResourceEncryptor 配合使用。
 *
 * 构建时 ResourceEncryptor 将敏感资源文件加密为 .fyr 格式。
 * 运行时 Java 层通过 NativeResource.decryptAsset() 获取解密内容。
 *
 * 加密文件格式 (.fyr):
 *   magic(4):     "FYR\0" (0x59524600)
 *   name_len(2):  原始文件名长度（字节）
 *   name(N):      原始文件名（UTF-8）
 *   iv(16):       AES 初始向量
 *   ciphertext:   AES-256-CBC 加密数据
 */
#include <jni.h>
#include <android/log.h>
#include <android/asset_manager_jni.h>
#include <string.h>
#include <stdlib.h>
#include "fy/crypto.h"

#define TAG "FY_RES"

/* 资源加密密钥（由 entry.c 设置） */
static uint8_t g_res_key[32] = {0};
static int g_res_key_set = 0;

/**
 * 设置资源解密密钥
 */
void fy_set_resource_key(const uint8_t key[32]) {
    memcpy(g_res_key, key, 32);
    g_res_key_set = 1;
    __android_log_print(ANDROID_LOG_INFO, TAG, "resource key set");
}

/* ============================================================
 * JNI: NativeResource.decryptAsset(Context, String assetPath)
 *
 * @param context   Application context
 * @param asset_path 资源路径（如 "config.json"）
 * @return byte[] 解密后的资源内容，失败返回 null
 * ============================================================ */
JNIEXPORT jbyteArray JNICALL
Java_com_fy_guard_stub_NativeResource_decryptAsset(JNIEnv *env, jclass clazz,
                                                   jobject context,
                                                   jstring asset_path) {
    if (!g_res_key_set) {
        __android_log_print(ANDROID_LOG_ERROR, TAG,
                            "resource key not set");
        return NULL;
    }

    const char *path = (*env)->GetStringUTFChars(env, asset_path, NULL);
    if (!path) return NULL;

    /* 构建加密文件路径: config.json → config.fyr */
    char enc_path[512];
    strncpy(enc_path, path, sizeof(enc_path) - 5);
    enc_path[sizeof(enc_path) - 5] = '\0';

    char *dot = strrchr(enc_path, '.');
    if (dot) {
        strcpy(dot, ".fyr");
    } else {
        strcat(enc_path, ".fyr");
    }

    (*env)->ReleaseStringUTFChars(env, asset_path, path);

    /* 读取加密文件 */
    jclass ctx_cls = (*env)->GetObjectClass(env, context);
    jmethodID get_am = (*env)->GetMethodID(env, ctx_cls, "getAssets",
                                           "()Landroid/content/res/AssetManager;");
    jobject am_obj = (*env)->CallObjectMethod(env, context, get_am);

    AAssetManager *mgr = AAssetManager_fromJava(env, am_obj);
    AAsset *asset = AAssetManager_open(mgr, enc_path, AASSET_MODE_BUFFER);

    if (!asset) {
        __android_log_print(ANDROID_LOG_WARN, TAG,
                            "encrypted asset not found: %s", enc_path);
        return NULL;
    }

    off_t asset_len = AAsset_getLength(asset);
    const void *asset_buf = AAsset_getBuffer(asset);

    if (asset_len < 6) {
        AAsset_close(asset);
        return NULL;
    }

    const uint8_t *data = (const uint8_t *)asset_buf;

    /* 校验魔数 "FYR\0" */
    if (data[0] != 0x59 || data[1] != 0x52 || data[2] != 0x46 || data[3] != 0x00) {
        __android_log_print(ANDROID_LOG_ERROR, TAG,
                            "bad magic in %s", enc_path);
        AAsset_close(asset);
        return NULL;
    }

    /* 解析头部 */
    uint16_t name_len;
    memcpy(&name_len, data + 4, 2);
    size_t header_size = 6 + name_len;

    if ((size_t)asset_len <= header_size + 16) {
        AAsset_close(asset);
        return NULL;
    }

    /* AES 解密 */
    const uint8_t *aes_data = data + header_size;
    size_t aes_size = (size_t)asset_len - header_size;

    uint8_t *decrypted = (uint8_t *)malloc(aes_size + 16);
    if (!decrypted) {
        AAsset_close(asset);
        return NULL;
    }

    int dec_len = fy_aes_cbc_decrypt(aes_data, aes_size, decrypted,
                                     g_res_key, aes_data /* IV 是 aes_data 的前 16 字节 */);

    AAsset_close(asset);

    if (dec_len < 0) {
        __android_log_print(ANDROID_LOG_ERROR, TAG,
                            "decryption failed for %s", enc_path);
        free(decrypted);
        return NULL;
    }

    __android_log_print(ANDROID_LOG_INFO, TAG,
                        "decrypted %s: %d bytes", enc_path, dec_len);

    /* 返回 Java byte[] */
    jbyteArray result = (*env)->NewByteArray(env, dec_len);
    if (result) {
        (*env)->SetByteArrayRegion(env, result, 0, dec_len,
                                   (const jbyte *)decrypted);
    }

    free(decrypted);
    return result;
}

/* ============================================================
 * JNI: NativeResource.initKey(Context, byte[] key)
 *
 * Java 层可以在 StubApplication 中调用此方法设置资源密钥。
 * 但密钥已经在 JNI_OnLoad 中自动派生并设置了，
 * 这个方法主要用于外部注入密钥的场景。
 * ============================================================ */
JNIEXPORT void JNICALL
Java_com_fy_guard_stub_NativeResource_initKey(JNIEnv *env, jclass clazz,
        jobject context,
jbyteArray key_arr) {
if (!key_arr) return;

jsize len = (*env)->GetArrayLength(env, key_arr);
if (len != 32) {
__android_log_print(ANDROID_LOG_ERROR, TAG,
"invalid key length: %d (expected 32)", len);
return;
}

(*env)->GetByteArrayRegion(env, key_arr, 0, 32, (jbyte *)g_res_key);
g_res_key_set = 1;

__android_log_print(ANDROID_LOG_INFO, TAG,
"resource key set from Java");
}
