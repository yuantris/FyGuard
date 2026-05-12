//
// Created by 方方大王 on 2026/5/13.
//
/*
 * crypto.h — AES-256-CBC + SHA-256 自包含实现
 *
 * 特点：
 *   1. Header-Only：一个头文件包含全部实现，零外部依赖
 *   2. 与 buildSrc 中的 AesCipher.kt 完全兼容（相同算法、相同数据格式）
 *   3. 支持 16KB 页面环境（所有内存操作使用标准 malloc）
 *
 * 算法：
 *   - AES-256: FIPS 197 标准，128-bit 分组，256-bit 密钥，14 轮
 *   - CBC 模式: Cipher Block Chaining，需要 16 字节 IV
 *   - PKCS7 填充: 标准填充方案
 *   - SHA-256: FIPS 180-4 标准
 *
 * 使用场景：
 *   构建阶段: AesCipher.kt 加密 DEX/SO/资源
 *   运行阶段: crypto.h 解密
 */
#ifndef FY_CRYPTO_H
#define FY_CRYPTO_H

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/* ============================================================
 * AES-256 S-Box (Substitution Box)
 * 用于 SubBytes 变换，提供非线性混淆
 * ============================================================ */
static const uint8_t FY_SBOX[256] = {
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

/* Inverse S-Box（用于 InvSubBytes） */
static const uint8_t FY_ISBOX[256] = {
        0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
        0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
        0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
        0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
        0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
        0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
        0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
        0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
        0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
        0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
        0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
        0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
        0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
        0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
        0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
        0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

/* Round Constants（密钥扩展轮常量） */
static const uint8_t FY_RCON[14] = {
        0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d
};

/* ============================================================
 * GF(2^8) 有限域运算
 * AES 的 MixColumns 步骤需要在 GF(2^8) 上做乘法
 * ============================================================ */

/* xtime: 乘以 2（在 GF(2^8) 中） */
static inline uint8_t fy_xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

/* gf_mul: GF(2^8) 通用乘法 */
static uint8_t fy_gf_mul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        uint8_t hi = a & 0x80;
        a = (uint8_t)(a << 1);
        if (hi) a ^= 0x1b;  // 不可约多项式 x^8 + x^4 + x^3 + x + 1
        b >>= 1;
    }
    return p;
}

/* ============================================================
 * AES-256 密钥扩展
 *
 * AES-256: Nk=8 (密钥字数), Nr=14 (轮数)
 * 从 32 字节密钥生成 240 字节扩展密钥
 * ============================================================ */
#define FY_EKS 240  /* (Nr+1) * 16 = 15 * 16 = 240 */

static void fy_key_expand(const uint8_t key[32], uint8_t ek[FY_EKS]) {
    /* 前 32 字节直接复制 */
    memcpy(ek, key, 32);

    uint8_t t[4];
    for (int i = 8; i < 60; i++) {  /* 60 个 4 字节字 = 240 字节 */
        memcpy(t, &ek[(i - 1) * 4], 4);

        if (i % 8 == 0) {
            /* RotWord + SubWord + Rcon */
            uint8_t c = t[0];
            t[0] = FY_SBOX[t[1]] ^ FY_RCON[i / 8 - 1];
            t[1] = FY_SBOX[t[2]];
            t[2] = FY_SBOX[t[3]];
            t[3] = FY_SBOX[c];
        } else if (i % 8 == 4) {
            /* SubWord（AES-256 特有） */
            t[0] = FY_SBOX[t[0]];
            t[1] = FY_SBOX[t[1]];
            t[2] = FY_SBOX[t[2]];
            t[3] = FY_SBOX[t[3]];
        }

        for (int j = 0; j < 4; j++)
            ek[i * 4 + j] = ek[(i - 8) * 4 + j] ^ t[j];
    }
}

/* ============================================================
 * AES 轮变换函数
 * ============================================================ */

/* SubBytes: 字节替换（通过 S-Box） */
static void fy_sub_bytes(uint8_t *s) {
    for (int i = 0; i < 16; i++) s[i] = FY_SBOX[s[i]];
}

/* InvSubBytes: 逆字节替换 */
static void fy_inv_sub_bytes(uint8_t *s) {
    for (int i = 0; i < 16; i++) s[i] = FY_ISBOX[s[i]];
}

/* ShiftRows: 行移位 */
static void fy_shift_rows(uint8_t *s) {
    uint8_t t;
    /* 第 1 行左移 1 */
    t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
    /* 第 2 行左移 2 */
    t = s[2]; s[2] = s[10]; s[10] = t;
    t = s[6]; s[6] = s[14]; s[14] = t;
    /* 第 3 行左移 3 */
    t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
}

/* InvShiftRows: 逆行移位 */
static void fy_inv_shift_rows(uint8_t *s) {
    uint8_t t;
    t = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t;
    t = s[2]; s[2] = s[10]; s[10] = t;
    t = s[6]; s[6] = s[14]; s[14] = t;
    t = s[3]; s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = t;
}

/* MixColumns: 列混合 */
static void fy_mix_columns(uint8_t *s) {
    for (int c = 0; c < 4; c++) {
        int i = c * 4;
        uint8_t a = s[i], b = s[i+1], d = s[i+2], e = s[i+3];
        s[i]   = fy_xtime(a) ^ (fy_xtime(b) ^ b) ^ d ^ e;
        s[i+1] = a ^ fy_xtime(b) ^ (fy_xtime(d) ^ d) ^ e;
        s[i+2] = a ^ b ^ fy_xtime(d) ^ (fy_xtime(e) ^ e);
        s[i+3] = (fy_xtime(a) ^ a) ^ b ^ d ^ fy_xtime(e);
    }
}

/* InvMixColumns: 逆列混合 */
static void fy_inv_mix_columns(uint8_t *s) {
    for (int c = 0; c < 4; c++) {
        int i = c * 4;
        uint8_t a = s[i], b = s[i+1], d = s[i+2], e = s[i+3];
        s[i]   = fy_gf_mul(a,14) ^ fy_gf_mul(b,11) ^ fy_gf_mul(d,13) ^ fy_gf_mul(e,9);
        s[i+1] = fy_gf_mul(a,9)  ^ fy_gf_mul(b,14) ^ fy_gf_mul(d,11) ^ fy_gf_mul(e,13);
        s[i+2] = fy_gf_mul(a,13) ^ fy_gf_mul(b,9)  ^ fy_gf_mul(d,14) ^ fy_gf_mul(e,11);
        s[i+3] = fy_gf_mul(a,11) ^ fy_gf_mul(b,13) ^ fy_gf_mul(d,9)  ^ fy_gf_mul(e,14);
    }
}

/* XOR 两个 16 字节块 */
static inline void fy_xor16(uint8_t *dst, const uint8_t *a, const uint8_t *b) {
    for (int i = 0; i < 16; i++) dst[i] = a[i] ^ b[i];
}

/* ============================================================
 * AES-256 单块加密 / 解密
 * ============================================================ */

/* 加密一个 16 字节块 */
static void fy_aes_encrypt(const uint8_t in[16], uint8_t out[16],
                           const uint8_t ek[FY_EKS]) {
    uint8_t s[16];
    memcpy(s, in, 16);

    /* 初始轮密钥加 */
    fy_xor16(s, s, ek);

    /* Nr-1 轮标准轮变换 */
    for (int r = 1; r < 14; r++) {
        fy_sub_bytes(s);
        fy_shift_rows(s);
        fy_mix_columns(s);
        fy_xor16(s, s, ek + r * 16);
    }

    /* 最后一轮（无 MixColumns） */
    fy_sub_bytes(s);
    fy_shift_rows(s);
    fy_xor16(s, s, ek + 14 * 16);

    memcpy(out, s, 16);
}

/* 解密一个 16 字节块 */
static void fy_aes_decrypt(const uint8_t in[16], uint8_t out[16],
                           const uint8_t ek[FY_EKS]) {
    uint8_t s[16];
    memcpy(s, in, 16);

    /* 初始轮密钥加（使用最后一轮密钥） */
    fy_xor16(s, s, ek + 14 * 16);

    /* Nr-1 轮逆变换 */
    for (int r = 13; r > 0; r--) {
        fy_inv_shift_rows(s);
        fy_inv_sub_bytes(s);
        fy_xor16(s, s, ek + r * 16);
        fy_inv_mix_columns(s);
    }

    /* 最后一轮 */
    fy_inv_shift_rows(s);
    fy_inv_sub_bytes(s);
    fy_xor16(s, s, ek);

    memcpy(out, s, 16);
}

/* ============================================================
 * AES-256-CBC 解密（含 PKCS7 去填充）
 *
 * @param in      密文数据
 * @param in_len  密文长度（必须是 16 的倍数）
 * @param out     输出缓冲区（调用者分配，至少 in_len 字节）
 * @param key     32 字节密钥
 * @param iv      16 字节初始向量
 * @return 解密后的明文长度，失败返回 -1
 * ============================================================ */
static int fy_aes_cbc_decrypt(const uint8_t *in, size_t in_len,
                              uint8_t *out,
                              const uint8_t key[32], const uint8_t iv[16]) {
    /* 校验输入 */
    if (in_len == 0 || in_len % 16 != 0) return -1;

    /* 密钥扩展 */
    uint8_t ek[FY_EKS];
    fy_key_expand(key, ek);

    /* CBC 解密：每个块先解密，再与前一个密文块 XOR */
    uint8_t prev[16];
    memcpy(prev, iv, 16);

    size_t nblocks = in_len / 16;
    for (size_t b = 0; b < nblocks; b++) {
        uint8_t decrypted[16];
        fy_aes_decrypt(in + b * 16, decrypted, ek);
        fy_xor16(out + b * 16, decrypted, prev);
        memcpy(prev, in + b * 16, 16);  // CBC: prev = 当前密文块
    }

    /* PKCS7 去填充 */
    uint8_t pad = out[in_len - 1];
    if (pad == 0 || pad > 16) return -1;

    /* 校验填充（所有填充字节必须等于 pad 值） */
    for (uint8_t i = 0; i < pad; i++) {
        if (out[in_len - 1 - i] != pad) return -1;
    }

    return (int)(in_len - pad);
}

/* ============================================================
 * SHA-256 哈希
 *
 * 用于完整性校验（校验解密后的数据是否被篡改）
 * ============================================================ */
static const uint32_t FY_SHA256_K[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static inline uint32_t fy_rotr(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

/**
 * 计算 SHA-256 哈希
 *
 * @param data 输入数据
 * @param len  数据长度
 * @param out  输出 32 字节哈希值
 */
static void fy_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    /* 初始哈希值（前 8 个素数的平方根小数部分） */
    uint32_t h[8] = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    /* 消息填充（长度后缀 + 1 + 0 填充 + 64-bit 长度） */
    size_t total = len + 1 + 8;
    size_t padded = ((total + 63) / 64) * 64;
    uint8_t *buf = (uint8_t *)calloc(1, padded);
    memcpy(buf, data, len);
    buf[len] = 0x80;  // 填充 1 bit

    /* 64-bit 大端长度 */
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++)
        buf[padded - 1 - i] = (uint8_t)(bits >> (i * 8));

    /* 处理每个 512-bit (64 字节) 块 */
    for (size_t off = 0; off < padded; off += 64) {
        uint32_t w[64];

        /* 消息调度 */
        for (int i = 0; i < 16; i++)
            w[i] = ((uint32_t)buf[off+i*4] << 24) |
                   ((uint32_t)buf[off+i*4+1] << 16) |
                   ((uint32_t)buf[off+i*4+2] << 8) |
                   (uint32_t)buf[off+i*4+3];

        for (int i = 16; i < 64; i++) {
            uint32_t s0 = fy_rotr(w[i-15],7) ^ fy_rotr(w[i-15],18) ^ (w[i-15] >> 3);
            uint32_t s1 = fy_rotr(w[i-2],17) ^ fy_rotr(w[i-2],19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }

        /* 压缩 */
        uint32_t v[8];
        memcpy(v, h, 32);

        for (int i = 0; i < 64; i++) {
            uint32_t S1 = fy_rotr(v[4],6) ^ fy_rotr(v[4],11) ^ fy_rotr(v[4],25);
            uint32_t ch = (v[4] & v[5]) ^ ((~v[4]) & v[6]);
            uint32_t t1 = v[7] + S1 + ch + FY_SHA256_K[i] + w[i];
            uint32_t S0 = fy_rotr(v[0],2) ^ fy_rotr(v[0],13) ^ fy_rotr(v[0],22);
            uint32_t maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            uint32_t t2 = S0 + maj;

            v[7] = v[6]; v[6] = v[5]; v[5] = v[4];
            v[4] = v[3] + t1;
            v[3] = v[2]; v[2] = v[1]; v[1] = v[0];
            v[0] = t1 + t2;
        }

        for (int i = 0; i < 8; i++) h[i] += v[i];
    }

    free(buf);

    /* 输出大端哈希值 */
    for (int i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(h[i] >> 24);
        out[i*4+1] = (uint8_t)(h[i] >> 16);
        out[i*4+2] = (uint8_t)(h[i] >> 8);
        out[i*4+3] = (uint8_t)h[i];
    }
}

/* ============================================================
 * 工具函数
 * ============================================================ */

/**
 * 十六进制字符串转字节数组
 * 用于从编译时注入的密钥字符串转换为字节
 */
static void fy_hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
    for (size_t i = 0; i < out_len; i++) {
        unsigned int b;
        sscanf(hex + i * 2, "%02x", &b);
        out[i] = (uint8_t)b;
    }
}

/**
 * 安全擦除内存（防止编译器优化掉擦除操作）
 */
static void fy_secure_zero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) *p++ = 0;
}

#endif /* FY_CRYPTO_H */

