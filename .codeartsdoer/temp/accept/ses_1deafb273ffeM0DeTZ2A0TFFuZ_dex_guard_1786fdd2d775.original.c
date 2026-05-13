//
// Created by 方方大王 on 2026/5/13.
//
/*
 * dex_guard.c — DEX 解密加载引擎
 *
 * 职责：
 *   1. 从 APK 的 assets/enc_dex.bin 读取加密的 DEX blob
 *   2. AES-256-CBC 解密
 *   3. SHA-256 完整性校验
 *   4. 创建 InMemoryDexClassLoader (API 26+) 或 DexClassLoader
 *   5. 将 ClassLoader 存入 NativeLoader.sClassLoader 静态字段
 *   6. 返回真实 Application 类名
 *
 * 加密格式 (enc_dex.bin):
 *   magic(4):       "FYHD" (0x44594846)
 *   version(4):     格式版本
 *   iv(16):         AES 初始向量
 *   sha256(32):     明文 SHA-256（完整性校验）
 *   ciphertext:     AES-256-CBC 加密的 DEX 数据
 *   总头部: 56 字节
 *
 * 加密的 DEX 数据格式:
 *   count(4):       DEX 文件数量
 *   [size(4) + data(size)] * count
 */
#include <jni.h>
#include <android/log.h>
#include <android/asset_manager_jni.h>
#include <stdlib.h>
#include <string.h>
#include "fy/crypto.h"
#include "fy/page.h"

#define TAG "FY_DEXGUARD"

/* enc_dex.bin 的魔数（与 buildSrc AesCipher.kt 一致） */
#define FYHD_MAGIC 0x44594846  /* "FYHD" in little-endian */

/* DEX 加密密钥（由 entry.c 通过 fy_set_dex_key 设置） */
static uint8_t g_dex_key[32] = {0};
static int g_dex_key_set = 0;

/**
 * 设置 DEX 解密密钥
 * 在 JNI_OnLoad 中由 entry.c 调用
 */
void fy_set_dex_key(const uint8_t key[32]) {
    memcpy(g_dex_key, key, 32);
    g_dex_key_set = 1;
}

/* ============================================================
 * 从 APK assets 中读取文件
 * ============================================================ */
static uint8_t *read_asset(JNIEnv *env, jobject context,
                           const char *name, size_t *out_size) {
    /* context.getAssets() */
    jclass ctx_cls = (*env)->GetObjectClass(env, context);
    jmethodID get_am = (*env)->GetMethodID(env, ctx_cls, "getAssets",
                                           "()Landroid/content/res/AssetManager;");
    jobject am_obj = (*env)->CallObjectMethod(env, context, get_am);
    if (!am_obj) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "getAssets() returned null");
        return NULL;
    }

    /* 通过 AAssetManager C API 读取 */
    AAssetManager *mgr = AAssetManager_fromJava(env, am_obj);
    AAsset *asset = AAssetManager_open(mgr, name, AASSET_MODE_BUFFER);
    if (!asset) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "asset not found: %s", name);
        return NULL;
    }

    off_t len = AAsset_getLength(asset);
    const void *buf = AAsset_getBuffer(asset);
    if (!buf) {
        AAsset_close(asset);
        return NULL;
    }

    /* 复制到堆内存 */
    uint8_t *data = (uint8_t *)malloc(len);
    if (!data) {
        AAsset_close(asset);
        return NULL;
    }
    memcpy(data, buf, len);
    *out_size = (size_t)len;

    AAsset_close(asset);

    __android_log_print(ANDROID_LOG_INFO, TAG,
                        "read asset '%s': %zu bytes", name, *out_size);
    return data;
}

/* ============================================================
 * 创建 ClassLoader
 *
 * 优先使用 InMemoryDexClassLoader（API 26+，不落盘），
 * 降级使用 DexClassLoader（写临时文件）。
 * ============================================================ */
static jobject create_classloader(JNIEnv *env, jobject context,
                                  const uint8_t *dex_data, size_t dex_len) {
    jclass ctx_cls = (*env)->GetObjectClass(env, context);
    jmethodID get_cl = (*env)->GetMethodID(env, ctx_cls, "getClassLoader",
                                           "()Ljava/lang/ClassLoader;");
    jobject parent = (*env)->CallObjectMethod(env, context, get_cl);

    if (dex_len < 4) return NULL;
    uint32_t dex_count;
    memcpy(&dex_count, dex_data, 4);
    __android_log_print(ANDROID_LOG_INFO, TAG, "DEX count: %u", dex_count);
    if (dex_count == 0) return NULL;

    typedef struct { const uint8_t *data; uint32_t size; } dex_entry_t;
    dex_entry_t *entries = (dex_entry_t *)malloc(sizeof(dex_entry_t) * dex_count);
    if (!entries) return NULL;

    const uint8_t *p = dex_data + 4;
    for (uint32_t i = 0; i < dex_count; i++) {
        if (p + 4 > dex_data + dex_len) { free(entries); return NULL; }
        memcpy(&entries[i].size, p, 4); p += 4;
        entries[i].data = p;
        p += entries[i].size;
        __android_log_print(ANDROID_LOG_INFO, TAG, "DEX[%u]: %u bytes", i, entries[i].size);
    }

    jclass imdl_cls = (*env)->FindClass(env, "dalvik/system/InMemoryDexClassLoader");
    if (imdl_cls && !(*env)->ExceptionCheck(env)) {
        __android_log_print(ANDROID_LOG_INFO, TAG, "using InMemoryDexClassLoader with %u DEX files", dex_count);
        jclass bb_cls = (*env)->FindClass(env, "java/nio/ByteBuffer");
        jmethodID wrap = (*env)->GetStaticMethodID(env, bb_cls, "wrap", "([B)Ljava/nio/ByteBuffer;");
        jobjectArray buf_array = (*env)->NewObjectArray(env, dex_count, bb_cls, NULL);
        for (uint32_t i = 0; i < dex_count; i++) {
            jbyteArray arr = (*env)->NewByteArray(env, (jint)entries[i].size);
            (*env)->SetByteArrayRegion(env, arr, 0, (jint)entries[i].size, (const jbyte *)entries[i].data);
            jobject buf = (*env)->CallStaticObjectMethod(env, bb_cls, wrap, arr);
            (*env)->SetObjectArrayElement(env, buf_array, i, buf);
            (*env)->DeleteLocalRef(env, arr);
            (*env)->DeleteLocalRef(env, buf);
        }
        jmethodID init = (*env)->GetMethodID(env, imdl_cls, "<init>", "([Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
        jobject cl = (*env)->NewObject(env, imdl_cls, init, buf_array, parent);
        (*env)->DeleteLocalRef(env, buf_array);
        free(entries);
        __android_log_print(ANDROID_LOG_INFO, TAG, "InMemoryDexClassLoader created with %u DEX files", dex_count);
        return cl;
    }

    (*env)->ExceptionClear(env);
    __android_log_print(ANDROID_LOG_INFO, TAG, "fallback to DexClassLoader (single DEX only)");
    jmethodID get_files = (*env)->GetMethodID(env, ctx_cls, "getFilesDir", "()Ljava/io/File;");
    jobject files_dir = (*env)->CallObjectMethod(env, context, get_files);
    jclass file_cls = (*env)->GetObjectClass(env, files_dir);
    jmethodID get_path = (*env)->GetMethodID(env, file_cls, "getPath", "()Ljava/lang/String;");
    jstring dir_str = (jstring)(*env)->CallObjectMethod(env, files_dir, get_path);
    const char *dir_c = (*env)->GetStringUTFChars(env, dir_str, NULL);
    char dex_path[512], opt_path[512];
    snprintf(dex_path, sizeof(dex_path), "%s/.fy_enc.dex", dir_c);
    snprintf(opt_path, sizeof(opt_path), "%s/.fy_opt", dir_c);
    (*env)->ReleaseStringUTFChars(env, dir_str, dir_c);
    FILE *f = fopen(dex_path, "wb");
    if (!f) { free(entries); __android_log_print(ANDROID_LOG_ERROR, TAG, "failed to open %s", dex_path); return NULL; }
    fwrite(entries[0].data, 1, entries[0].size, f);
    fclose(f);
    jclass dcl_cls = (*env)->FindClass(env, "dalvik/system/DexClassLoader");
    jmethodID dcl_init = (*env)->GetMethodID(env, dcl_cls, "<init>", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V");
    jstring js_dex = (*env)->NewStringUTF(env, dex_path);
    jstring js_opt = (*env)->NewStringUTF(env, opt_path);
    jstring js_lib = (*env)->NewStringUTF(env, "");
    jobject cl = (*env)->NewObject(env, dcl_cls, dcl_init, js_dex, js_opt, js_lib, parent);
    (*env)->DeleteLocalRef(env, js_dex);
    (*env)->DeleteLocalRef(env, js_opt);
    (*env)->DeleteLocalRef(env, js_lib);
    free(entries);
    __android_log_print(ANDROID_LOG_INFO, TAG, "DexClassLoader created: %s", dex_path);
    return cl;
}

/* ============================================================
 * DEX 加载主入口
 *
 * 由 JNI_OnLoad → entry.c 调用，
 * 也被 StubApplication.attachBaseContext 通过 JNI 调用。
 * ============================================================ */
int fy_init_dex(JNIEnv *env, jobject context) {
    /* 1. 读取加密 DEX */
    size_t enc_len = 0;
    uint8_t *enc = read_asset(env, context, "enc_dex.bin", &enc_len);
    if (!enc) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "enc_dex.bin not found");
        return -1;
    }

    /* 2. 校验最小大小 (header = 56 bytes) */
    if (enc_len < 56) {
        __android_log_print(ANDROID_LOG_ERROR, TAG,
                            "enc_dex.bin too small: %zu bytes", enc_len);
        free(enc);
        return -1;
    }

    /* 3. 校验魔数 */
    uint32_t magic;
    memcpy(&magic, enc, 4);
    if (magic != FYHD_MAGIC) {
        __android_log_print(ANDROID_LOG_ERROR, TAG,
                            "bad magic: 0x%08x (expected 0x%08x)",
                            magic, FYHD_MAGIC);
        free(enc);
        return -1;
    }

    /* 4. 解析 header */
    const uint8_t *iv   = enc + 8;       /* offset 8:  IV (16 bytes) */
    const uint8_t *sha  = enc + 24;      /* offset 24: SHA-256 (32 bytes) */
    const uint8_t *ct   = enc + 56;      /* offset 56: ciphertext */
    size_t ct_len        = enc_len - 56;

    /* 5. AES-CBC 解密 */
    uint8_t *plain = (uint8_t *)malloc(ct_len + 16);
    if (!plain) { free(enc); return -1; }

    int dec_len = fy_aes_cbc_decrypt(ct, ct_len, plain, g_dex_key, iv);
    if (dec_len < 0) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "AES decryption failed");
        free(enc);
        free(plain);
        return -1;
    }

    __android_log_print(ANDROID_LOG_INFO, TAG,
                        "decrypted: %zu → %d bytes", enc_len, dec_len);

    /* 6. 完整性校验 */
    uint8_t computed_sha[32];
    fy_sha256(plain, (size_t)dec_len, computed_sha);
    if (memcmp(computed_sha, sha, 32) != 0) {
        __android_log_print(ANDROID_LOG_ERROR, TAG,
                            "SHA-256 integrity check FAILED!");
        free(enc);
        free(plain);
        return -1;
    }

    __android_log_print(ANDROID_LOG_INFO, TAG, "integrity check passed");

    /* 7. 创建 ClassLoader */
    jobject cl = create_classloader(env, context, plain, (size_t)dec_len);
    free(plain);
    free(enc);

    if (!cl) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "ClassLoader creation failed");
        return -1;
    }

    /* 8. 存入 NativeLoader.sClassLoader 静态字段 */
    jclass nl_cls = (*env)->FindClass(env, "com/fy/guard_stub/NativeLoader");
    if (!nl_cls) {
        __android_log_print(ANDROID_LOG_ERROR, TAG,
                            "NativeLoader class not found");
        (*env)->ExceptionClear(env);
        return -1;
    }

    jfieldID cl_field = (*env)->GetStaticFieldID(env, nl_cls,
                                                 "sClassLoader", "Ljava/lang/ClassLoader;");
    jobject global_cl = (*env)->NewGlobalRef(env, cl);
    (*env)->SetStaticObjectField(env, nl_cls, cl_field, global_cl);

    __android_log_print(ANDROID_LOG_INFO, TAG,
                        "NativeLoader.sClassLoader set");

    /* 9. Inject decrypt ClassLoader into PathClassLoader parent chain
     *
     * System loads ContentProviders via LoadedApk.mClassLoader
     * (PathClassLoader), whose parent is BootClassLoader.
     * We insert our decryption ClassLoader between them:
     *   PathClassLoader -> DecryptClassLoader -> BootClassLoader
     *
     * Without this, classes from enc_dex.bin (like
     * androidx.startup.InitializationProvider) are invisible
     * to the system class loading path.
     *
     * IMPORTANT: parent is a private field of java.lang.ClassLoader,
     * so we must use ClassLoader.class.getDeclaredField(), NOT the
     * subclass's class.
     */
    {
        jclass ctx_cls2 = (*env)->GetObjectClass(env, context);
        jmethodID get_cl2 = (*env)->GetMethodID(env, ctx_cls2, "getClassLoader",
                                                 "()Ljava/lang/ClassLoader;");
        jobject path_cl = (*env)->CallObjectMethod(env, context, get_cl2);

        if (!path_cl) {
            __android_log_print(ANDROID_LOG_WARN, TAG, "context.getClassLoader() returned null");
        } else {
            /* Use java.lang.ClassLoader.class to access the private "parent" field */
            jclass cl_loader_cls = (*env)->FindClass(env, "java/lang/ClassLoader");
            jmethodID get_df = (*env)->GetStaticMethodID(env, cl_loader_cls, "getDeclaredField",
                                                         "(Ljava/lang/String;)Ljava/lang/reflect/Field;");

            jstring js_parent = (*env)->NewStringUTF(env, "parent");
            jobject parent_field = (*env)->CallStaticObjectMethod(env, cl_loader_cls, get_df, js_parent);
            (*env)->DeleteLocalRef(env, js_parent);

            if (!parent_field) {
                __android_log_print(ANDROID_LOG_WARN, TAG, "failed to get ClassLoader.parent field");
            } else {
                jclass fld_cls = (*env)->GetObjectClass(env, parent_field);
                jmethodID set_acc = (*env)->GetMethodID(env, fld_cls, "setAccessible", "(Z)V");
                jmethodID fld_get = (*env)->GetMethodID(env, fld_cls, "get",
                                                       "(Ljava/lang/Object;)Ljava/lang/Object;");
                jmethodID fld_set = (*env)->GetMethodID(env, fld_cls, "set",
                                                       "(Ljava/lang/Object;Ljava/lang/Object;)V");

                /* Make accessible */
                (*env)->CallVoidMethod(env, parent_field, set_acc, JNI_TRUE);

                /* Step 1: Save original parent (BootClassLoader) */
                jobject orig_parent = (*env)->CallObjectMethod(env, parent_field, fld_get, path_cl);
                __android_log_print(ANDROID_LOG_INFO, TAG, "PathCL original parent saved");

                /* Step 2: Set PathClassLoader.parent = DecryptClassLoader */
                (*env)->CallVoidMethod(env, parent_field, fld_set, path_cl, global_cl);
                __android_log_print(ANDROID_LOG_INFO, TAG, "PathCL.parent = DecryptCL");

                /* Step 3: Set DecryptClassLoader.parent = BootClassLoader (orig_parent) */
                (*env)->CallVoidMethod(env, parent_field, fld_set, cl, orig_parent);
                __android_log_print(ANDROID_LOG_INFO, TAG, "DecryptCL.parent = BootCL");

                __android_log_print(ANDROID_LOG_INFO, TAG,
                    "ClassLoader chain: PathCL -> DecryptCL -> BootCL");

                (*env)->DeleteLocalRef(env, orig_parent);
                (*env)->DeleteLocalRef(env, parent_field);
            }
        }
    }

    /* 9. 安全擦除密钥 */
    fy_secure_zero(g_dex_key, 32);

    return 0;
}
