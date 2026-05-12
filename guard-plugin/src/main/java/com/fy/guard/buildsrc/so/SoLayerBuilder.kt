package com.fy.guard.buildsrc.so

import com.fy.guard.buildsrc.SoProtection
import com.fy.guard.buildsrc.crypto.AesCipher
import org.gradle.api.logging.Logger
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * SO 代码段保护器（第四代加固）
 *
 * 原理：
 *   1. 解析 ELF，找到 .text section（代码段）
 *   2. AES-256-CBC 加密 .text 的内容
 *   3. 将加密数据追加到 .so 文件末尾（自定义 .fytext section）
 *   4. 运行时 native 层通过 __attribute__((constructor)) 自动触发：
 *      - 读取 .fytext section
 *      - mmap 新的可执行内存（16K 页面对齐）
 *      - AES 解密到新内存
 *      - 设置 R-X 权限（不可写，防篡改）
 *      - 跳转执行解密后的代码
 *
 * 16K 兼容的关键：
 *   - 永远不修改原始 .so 的 .text 段（不调用 mprotect 修改原始段）
 *   - mmap 分配的内存天然按系统页大小对齐
 *   - 彻底避免你之前遇到的 SEGV_ACCERR 崩溃
 */
class SoLayerBuilder(private val logger: Logger) {

    /**
     * 保护指定目录下的 SO 文件
     */
    fun protect(apkDir: File, config: SoProtection, key: ByteArray) {
        val libDir = File(apkDir, "lib/arm64-v8a")
        if (!libDir.exists()) {
            logger.warn("    lib/arm64-v8a not found, skipping SO protection")
            return
        }

        // 确定要保护的 SO 文件列表
        val targetLibs = if (config.libraries.isEmpty()) {
            // 保护所有 .so 文件
            libDir.listFiles()?.filter { it.extension == "so" } ?: emptyList()
        } else {
            // 只保护用户指定的 .so
            config.libraries.map { name -> File(libDir, name) }.filter { it.exists() }
        }

        logger.lifecycle("    target libraries: ${targetLibs.map { it.name }}")

        for (soFile in targetLibs) {
            encryptTextSection(soFile, key)
        }
    }

    /**
     * 加密单个 SO 的 .text section
     */
    private fun encryptTextSection(soFile: File, key: ByteArray) {
        logger.lifecycle("    processing: ${soFile.name}")

        val data = soFile.readBytes()

        // ===== 解析 ELF header (64-bit) =====
        if (data.size < 64) {
            logger.warn("    file too small, skipping")
            return
        }

        // 校验 ELF magic
        if (data[0] != 0x7F.toByte() || data[1] != 'E'.code.toByte() ||
            data[2] != 'L'.code.toByte() || data[3] != 'F'.code.toByte()) {
            logger.warn("    not a valid ELF file, skipping")
            return
        }

        // 检查是否 64-bit
        if (data[4].toInt() != 2) {
            logger.warn("    not a 64-bit ELF, skipping")
            return
        }

        val buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)

        // ELF64 header 关键字段
        val e_shoff = buf.getLong(40)        // section header table 偏移
        val e_shentsize = buf.getShort(58).toInt() and 0xFFFF  // 每个 section header 大小
        val e_shnum = buf.getShort(60).toInt() and 0xFFFF      // section header 数量
        val e_shstrndx = buf.getShort(62).toInt() and 0xFFFF   // section name string table 索引

        // ===== 读取 section header string table =====
        val shstrtabHeaderOff = (e_shoff + e_shstrndx * e_shentsize).toInt()
        val shstrtabOffset = buf.getLong(shstrtabHeaderOff + 24).toInt()  // sh_offset
        val shstrtabSize = buf.getLong(shstrtabHeaderOff + 32).toInt()    // sh_size
        val shstrtab = data.copyOfRange(shstrtabOffset, shstrtabOffset + shstrtabSize)

        // ===== 查找 .text section =====
        var textOffset = -1
        var textSize = -1

        for (i in 0 until e_shnum) {
            val shOff = (e_shoff + i * e_shentsize).toInt()
            val shNameIdx = buf.getInt(shOff)  // sh_name
            val name = readCString(shstrtab, shNameIdx)

            if (name == ".text") {
                textOffset = buf.getLong(shOff + 24).toInt()  // sh_offset
                textSize = buf.getLong(shOff + 32).toInt()    // sh_size
                break
            }
        }

        if (textOffset < 0 || textSize <= 0) {
            logger.warn("    .text section not found, skipping")
            return
        }

        logger.lifecycle("    .text: offset=0x${textOffset.toString(16)}, size=$textSize bytes")

        // ===== 加密 .text section =====
        val textData = data.copyOfRange(textOffset, textOffset + textSize)
        val encrypted = AesCipher.encryptWithHeader(textData, key, 0x54594646) // "FYT\0"

        logger.lifecycle("    .fytext: ${encrypted.size} bytes encrypted")

        // ===== 追加到文件末尾 =====
        val newData = data.copyOf(data.size + encrypted.size)
        System.arraycopy(encrypted, 0, newData, data.size, encrypted.size)

        soFile.writeBytes(newData)
        logger.lifecycle("    ${soFile.name}: updated (${data.size} → ${newData.size} bytes)")
    }

    /**
     * 从字节数组中读取 C 风格字符串（以 null 结尾）
     */
    private fun readCString(data: ByteArray, offset: Int): String {
        if (offset >= data.size) return ""
        var end = offset
        while (end < data.size && data[end] != 0.toByte()) end++
        return String(data, offset, end - offset, Charsets.US_ASCII)
    }
}
