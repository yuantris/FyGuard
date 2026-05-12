package com.fy.guard.buildsrc.res

import com.fy.guard.buildsrc.crypto.AesCipher
import org.gradle.api.logging.Logger
import java.io.File

/**
 * 资源文件加密器
 *
 * 加密 assets/ 和 res/ 中的敏感文件（配置、密钥、数据库等）。
 * 加密后的文件扩展名改为 .fyr，运行时通过 JNI 按需解密。
 *
 * 加密文件格式:
 *   magic(4):     "FYR\0" (0x59524600)
 *   name_len(2):  原始文件名长度
 *   name(N):      原始文件名（UTF-8）
 *   iv(16):       AES 初始向量
 *   ciphertext:   AES-256-CBC 加密数据
 */
class ResourceEncryptor(private val logger: Logger) {

    /** 可加密的文件扩展名 */
    private val encryptableExtensions = setOf(
        "json", "xml", "txt", "cfg", "conf", "properties",
        "dat", "bin", "db", "sqlite", "key", "pem",
        "html", "js", "css", "svg", "proto"
    )

    companion object {
        /** 加密文件魔数 */
        val MAGIC = byteArrayOf(0x59, 0x52, 0x46, 0x00) // "FYR\0"
    }

    /**
     * 加密目录中的敏感文件
     *
     * @param apkDir APK 解压目录
     * @param key    AES 密钥
     * @return 加密的文件数量
     */
    fun encrypt(apkDir: File, key: ByteArray): Int {
        var count = 0

        // 加密 assets/ 目录
        val assetsDir = File(apkDir, "assets")
        if (assetsDir.exists()) {
            count += encryptDirectory(assetsDir, key, "assets")
        }

        // 加密 res/raw/ 目录
        val rawDir = File(apkDir, "res/raw")
        if (rawDir.exists()) {
            count += encryptDirectory(rawDir, key, "res/raw")
        }

        logger.lifecycle("    encrypted $count resource files")
        return count
    }

    private fun encryptDirectory(dir: File, key: ByteArray, prefix: String): Int {
        var count = 0

        dir.walkTopDown()
            .filter { it.isFile }
            .filter { it.extension.lowercase() in encryptableExtensions }
            .filter { it.name != "enc_dex.bin" && it.name != "enc_methods.bin" && it.name != "integrity.dat" }
            .forEach { file ->
                try {
                    val plainData = file.readBytes()
                    val nameBytes = file.name.toByteArray(Charsets.UTF_8)

                    // 构建头部
                    val header = MAGIC +
                            byteArrayOf(
                                (nameBytes.size and 0xFF).toByte(),
                                (nameBytes.size shr 8 and 0xFF).toByte()
                            ) +
                            nameBytes

                    // AES 加密
                    val encrypted = AesCipher.encrypt(plainData, key)

                    // 写入加密文件（扩展名改为 .fyr）
                    val outFile = File(file.parent, file.nameWithoutExtension + ".fyr")
                    outFile.writeBytes(header + encrypted)

                    // 删除原始文件
                    file.delete()

                    logger.lifecycle("    ${file.name} → ${outFile.name} " +
                            "(${plainData.size} → ${header.size + encrypted.size} bytes)")
                    count++
                } catch (e: Exception) {
                    logger.warn("    failed to encrypt ${file.name}: ${e.message}")
                }
            }

        return count
    }
}
