package com.fy.guard.buildsrc.crypto

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * AES-256-CBC 加密引擎（纯 JVM 实现）
 *
 * 用于构建阶段的 DEX/SO/资源加密。
 * 运行阶段的解密由 native 层（crypto.h）完成。
 *
 * 两个实现使用相同的算法和数据格式，确保互操作。
 */
object AesCipher {

    /**
     * 从主密钥派生子密钥
     *
     * 不同用途使用不同的 purpose 字符串，确保密钥独立。
     * 即使 DEX 密钥泄露，SO 密钥和资源密钥仍然安全。
     *
     * @param masterHex 主密钥（64 位十六进制）
     * @param purpose   用途标识（如 "DEX_GUARD"、"SO_PROTECT"）
     * @return 32 字节派生密钥
     */
    fun deriveKey(masterHex: String, purpose: String): ByteArray {
        val master = hexToBytes(masterHex)
        val input = master + purpose.toByteArray(Charsets.UTF_8)
        return sha256(input)
    }

    /**
     * AES-256-CBC 加密（含 PKCS7 填充）
     *
     * @param plaintext 明文数据
     * @param key       32 字节密钥
     * @return IV(16) + 密文
     */
    fun encrypt(plaintext: ByteArray, key: ByteArray): ByteArray {
        require(key.size == 32) { "AES-256 requires 32-byte key, got ${key.size}" }

        val iv = ByteArray(16)
        java.security.SecureRandom().nextBytes(iv)

        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(key, "AES"),
            IvParameterSpec(iv)
        )
        val ciphertext = cipher.doFinal(plaintext)

        // 返回格式: IV(16) + ciphertext
        return iv + ciphertext
    }

    /**
     * AES-256-CBC 解密
     *
     * @param data IV(16) + 密文
     * @param key  32 字节密钥
     * @return 明文数据
     */
    fun decrypt(data: ByteArray, key: ByteArray): ByteArray {
        require(key.size == 32) { "AES-256 requires 32-byte key" }
        require(data.size > 16) { "Data must be > 16 bytes (at least IV)" }

        val iv = data.copyOfRange(0, 16)
        val ciphertext = data.copyOfRange(16, data.size)

        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(key, "AES"),
            IvParameterSpec(iv)
        )
        return cipher.doFinal(ciphertext)
    }

    /**
     * SHA-256 哈希
     */
    fun sha256(data: ByteArray): ByteArray {
        return MessageDigest.getInstance("SHA-256").digest(data)
    }

    /**
     * 带完整头部的加密（与 native 层 crypto.h 的 fy_cbc_dec 兼容）
     *
     * 输出格式:
     *   magic(4)        - 魔数标识，用于校验
     *   version(4)      - 格式版本
     *   iv(16)          - AES 初始向量
     *   sha256(32)      - 明文的 SHA-256（完整性校验）
     *   ciphertext      - AES-256-CBC 加密数据
     *
     * 总头部大小: 56 字节
     *
     * @param plaintext 明文
     * @param key       32 字节密钥
     * @param magic     4 字节魔数
     * @return 完整的加密 blob
     */
    fun encryptWithHeader(plaintext: ByteArray, key: ByteArray, magic: Int): ByteArray {
        // 1. 生成随机 IV
        val iv = ByteArray(16)
        java.security.SecureRandom().nextBytes(iv)

        // 2. 计算明文的 SHA-256（用于运行时完整性校验）
        val sha = sha256(plaintext)

        // 3. AES-CBC 加密
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(key, "AES"),
            IvParameterSpec(iv)
        )
        val ciphertext = cipher.doFinal(plaintext)

        // 4. 构建头部 (56 bytes)
        val header = ByteBuffer.allocate(56).order(ByteOrder.LITTLE_ENDIAN)
            .putInt(magic)      // offset 0:  魔数
            .putInt(1)          // offset 4:  版本号
            .put(iv)            // offset 8:  IV (16 bytes)
            .put(sha)           // offset 24: SHA-256 (32 bytes)
            .array()

        return header + ciphertext
    }

    /**
     * 十六进制字符串转字节数组
     */
    fun hexToBytes(hex: String): ByteArray {
        require(hex.length % 2 == 0) { "Hex string must have even length" }
        return ByteArray(hex.length / 2) { i ->
            hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }
}
