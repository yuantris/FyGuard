//
// Created by 方方大王 on 2026/5/13.
//
/*
 * method_restore.c — 函数抽取运行时还原引擎
 *
 * 配合 buildSrc 的 MethodExtractor 使用。
 *
 * 工作流程：
 *   1. 初始化时从 assets/enc_methods.bin 读取加密方法体 blob
 *   2. AES-256-CBC 解密所有方法体到内存
 *   3. 建立 method_idx → 方法体数据 的索引
 *   4. 当被保护的方法被调用时（通过 JNI 拦截），
 *      从索引中找到原始方法体，写回 DEX 内存中的 code_item
 *
 * 加密格式 (enc_methods.bin):
 *   header (16 bytes):
 *     magic(4):       "FMTH" (0x48544D46)
 *     version(4):     格式版本
 *     method_count(4): 方法数量
 *     index_size(4):   索引表大小（字节）
 *   index table (method_count * 16 bytes):
 *     [method_idx(4) + body_offset(4) + body_size(4) + meta(4)] * count
 *   encrypted data:
 *     iv(16) + AES-CBC ciphertext + sha256(32)
 */
#include <jni.h>
#include <android/log.h>
#include <string.h>
#include <stdlib.h>
#include "fy/crypto.h"

#define TAG "FY_METHOD"

/* 加密 blob 魔数 */
#define FMTH_MAGIC 0x48544D46  /* "FMTH" in little-endian */

/* ============================================================
 * 方法索引条目
 * 与 buildSrc MethodExtractor 中的写入格式一致
 * ============================================================ */
typedef struct {
    uint32_t method_idx;    /* DEX method_id 索引 */
    uint32_t body_offset;   /* 方法体在解密缓冲区中的偏移 */
    uint32_t body_size;     /* 方法体字节码大小（字节） */
    uint32_t meta;          /* 高 16 位 = registersSize, 低 16 位 = insSize */
} fy_method_entry_t;

/* 运行时状态 */
static fy_method_entry_t *g_entries = NULL;      /* 方法索引表 */
static uint32_t g_entry_count = 0;                /* 方法数量 */
static uint8_t *g_decrypted_bodies = NULL;        /* 解密后的方法体数据 */
static size_t   g_decrypted_size = 0;             /* 方法体数据总大小 */
static uint8_t  g_method_key[32] = {0};           /* 方法体解密密钥 */
static int      g_initialized = 0;

/**
 * 设置方法体解密密钥
 */
void fy_set_method_key(const uint8_t key[32]) {
    memcpy(g_method_key, key, 32);
}

/**
 * 初始化方法还原引擎
 *
 * @param env     JNI 环境
 * @param context Application context
 * @return 0 成功, -1 失败
 */
int fy_init_methods(JNIEnv *env, jobject context) {
    if (g_initialized) return 0;

    /* 读取加密 blob */
    jclass ctx_cls = (*env)->GetObjectClass(env, context);
    jmethodID get_am = (*env)->GetMethodID(env, ctx_cls, "getAssets",
                                           "()Landroid/content/res/AssetManager;");
    jobject am_obj = (*env)->CallObjectMethod(env, context, get_am);
    if (!am_obj) return -1;

    jclass am_cls = (*env)->GetObjectClass(env, am_obj);
    jmethodID open = (*env)->GetMethodID(env, am_cls, "open",
                                         "(Ljava/lang/String;)Ljava/io/InputStream;");
    jstring fname = (*env)->NewStringUTF(env, "enc_methods.bin");
    jobject is = (*env)->CallObjectMethod(env, am_obj, open, fname);

    if (!is) {
        __android_log_print(ANDROID_LOG_WARN, TAG,
                            "enc_methods.bin not found (no method protection)");
        (*env)->ExceptionClear(env);
        return -1;
    }

    /* 读取所有字节到内存 */
    jclass is_cls = (*env)->GetObjectClass(env, is);
    jmethodID available = (*env)->GetMethodID(env, is_cls, "available", "()I");
    jint file_size = (*env)->CallIntMethod(env, is, available);

    if (file_size < 16) return -1;

    jbyteArray buf = (*env)->NewByteArray(env, file_size);
    jmethodID read_m = (*env)->GetMethodID(env, is_cls, "read", "([BII)I");
    jint total_read = 0;
    while (total_read < file_size) {
        jint n = (*env)->CallIntMethod(env, is, read_m, buf, total_read,
                                       file_size - total_read);
        if (n <= 0) break;
        total_read += n;
    }

    jbyte *raw = (*env)->GetByteArrayElements(env, buf, NULL);

    /* 解析 header */
    const uint8_t *p = (const uint8_t *)raw;
    uint32_t magic, version, count, index_size;
    memcpy(&magic, p, sizeof(magic)); p += 4;
    memcpy(&version, p, sizeof(version)); p += 4;
    memcpy(&count, p, sizeof(count)); p += 4;
    memcpy(&index_size, p, sizeof(index_size)); p += 4;

    if (magic != FMTH_MAGIC) {
        __android_log_print(ANDROID_LOG_ERROR, TAG,
                            "bad magic: 0x%08x", magic);
        (*env)->ReleaseByteArrayElements(env, buf, raw, JNI_ABORT);
        return -1;
    }

    /* 读取索引表 */
    g_entry_count = count;
    g_entries = (fy_method_entry_t *)malloc(count * sizeof(fy_method_entry_t));
    memcpy(g_entries, p, count * sizeof(fy_method_entry_t));
    p += index_size;

    /* 解密方法体数据: iv(16) + ciphertext + sha256(32) */
    size_t remaining = (size_t)(file_size - (p - (const uint8_t *)raw));
    if (remaining < 16 + 32) {
        free(g_entries); g_entries = NULL;
        (*env)->ReleaseByteArrayElements(env, buf, raw, JNI_ABORT);
        return -1;
    }

    const uint8_t *iv = p;
    const uint8_t *ct = p + 16;
    size_t ct_size = remaining - 16 - 32;
    const uint8_t *expected_sha = p + 16 + ct_size;

    g_decrypted_bodies = (uint8_t *)malloc(ct_size + 16);
    int dec_len = fy_aes_cbc_decrypt(ct, ct_size, g_decrypted_bodies,
                                     g_method_key, iv);

    (*env)->ReleaseByteArrayElements(env, buf, raw, JNI_ABORT);

    if (dec_len < 0) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "method body decryption failed");
        free(g_entries); g_entries = NULL;
        free(g_decrypted_bodies); g_decrypted_bodies = NULL;
        return -1;
    }

    g_decrypted_size = (size_t)dec_len;

    /* 完整性校验 */
    uint8_t computed_sha[32];
    fy_sha256(g_decrypted_bodies, g_decrypted_size, computed_sha);
    if (memcmp(computed_sha, expected_sha, 32) != 0) {
        __android_log_print(ANDROID_LOG_ERROR, TAG,
                            "method body integrity check FAILED!");
        free(g_entries); g_entries = NULL;
        free(g_decrypted_bodies); g_decrypted_bodies = NULL;
        return -1;
    }

    /* 安全擦除密钥 */
    fy_secure_zero(g_method_key, 32);
    g_initialized = 1;

    __android_log_print(ANDROID_LOG_INFO, TAG,
                        "method restore initialized: %u methods, %zu bytes",
                        count, g_decrypted_size);

    return 0;
}

/**
 * 查找指定方法的原始字节码
 *
 * @param method_idx DEX method_id 索引
 * @param out_size   输出字节码大小
 * @return 字节码指针，未找到返回 NULL
 */
const uint8_t *fy_get_method_body(uint32_t method_idx, uint32_t *out_size) {
    if (!g_initialized) return NULL;

    for (uint32_t i = 0; i < g_entry_count; i++) {
        if (g_entries[i].method_idx == method_idx) {
            *out_size = g_entries[i].body_size;
            return g_decrypted_bodies + g_entries[i].body_offset;
        }
    }

    return NULL;
}
