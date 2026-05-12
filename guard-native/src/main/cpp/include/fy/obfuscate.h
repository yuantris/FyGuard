//
// Created by 方方大王 on 2026/5/13.
//
/*
 * obfuscate.h — 编译期字符串加密
 *
 * 目的：
 *   防止 strings 命令或 IDA 的字符串窗口直接看到敏感文本。
 *   在二进制中，所有字符串都被 XOR 加密，运行时按需解密到栈上。
 *
 * 用法：
 *   方法 1: 在源码中直接使用 FY_OBF_STR("敏感字符串")
 *   方法 2: 用 build tool 预处理源码中的字符串
 *
 * 当前实现：手动加密 + 运行时解密
 * 生产环境建议：用 Python 脚本扫描源码中的 OBF 调用，自动生成加密数据
 */
#ifndef FY_OBFUSCATE_H
#define FY_OBFUSCATE_H

#include <stdint.h>
#include <string.h>

/**
 * XOR 密钥生成器
 * 基于索引 i 生成伪随机 XOR 字节
 * 不同位置的字符使用不同的 XOR 值
 */
#define FY_OBF_SEED  0xA7B3C9D1
#define FY_OBF_KEY(i) ((uint8_t)((FY_OBF_SEED >> (((i) % 8) * 3)) ^ (0x5A + (i))))

/**
 * 栈上缓冲区（用于存放解密后的字符串）
 * 每次调用都会在栈上分配，函数返回后自动销毁
 */
typedef struct {
    char buf[256];
} fy_obf_buf;

/**
 * 解密字符串到栈缓冲区
 *
 * @param enc   加密的字节数组
 * @param len   长度
 * @param out   输出缓冲区
 * @return 指向解密后字符串的指针（即 out->buf）
 */
static inline const char *fy_obf_decrypt(const uint8_t *enc, size_t len, fy_obf_buf *out) {
    for (size_t i = 0; i < len; i++) {
        out->buf[i] = (char)(enc[i] ^ FY_OBF_KEY(i));
    }
    out->buf[len] = '\0';
    return out->buf;
}

/**
 * 手动加密辅助宏
 *
 * 声明一个加密的字符串常量：
 *   FY_OBF_DECL(my_secret, encrypted_bytes, length);
 *
 * 使用时解密到栈上：
 *   FY_OBF_USE(my_secret, name);
 *   printf("%s\n", name);  // name 是栈上的明文字符串
 */
#define FY_OBF_DECL(name, enc_array, enc_len) \
    static const uint8_t name##_enc[] = enc_array; \
    static const size_t  name##_len = enc_len

#define FY_OBF_USE(name, out_var) \
    fy_obf_buf _fy_obf_##out_var; \
    const char *out_var = fy_obf_decrypt(name##_enc, name##_len, &_fy_obf_##out_var)

/**
 * 便捷日志宏（自动加密格式字符串）
 *
 * 注意：这只是示例，生产环境应该用 build tool 自动处理
 * 这里为了编译通过，直接使用明文
 */
#define FY_LOGI(tag, fmt, ...) \
    __android_log_print(ANDROID_LOG_INFO, tag, fmt, ##__VA_ARGS__)

#define FY_LOGE(tag, fmt, ...) \
    __android_log_print(ANDROID_LOG_ERROR, tag, fmt, ##__VA_ARGS__)

#endif /* FY_OBFUSCATE_H */

