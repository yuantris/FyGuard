package com.fy.guard.buildsrc.dex

import com.fy.guard.buildsrc.crypto.AesCipher
import org.gradle.api.logging.Logger
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * DEX 函数抽取引擎（第二代加固核心）
 *
 * 原理：
 *   1. 解析 DEX，找到所有可保护的方法
 *   2. 提取每个方法的字节码（code_item.insns）
 *   3. 用 stub 字节码替换（stub 只包含 return-void）
 *   4. 原始字节码 AES 加密为 blob，存入 assets/enc_methods.bin
 *
 * 运行时：
 *   StubApplication 启动后，native 层加载 enc_methods.bin。
 *   当被保护的方法首次被调用时（通过 JNI 拦截），
 *   native 层从 blob 中找到对应方法体，AES 解密，
 *   写回 DEX 内存中的 code_item，方法即可正常执行。
 *
 * 安全效果：
 *   Frida dump 出来的 DEX 中，被保护的方法体全是 return-void。
 *   只有在运行时调用过的方法才有明文字节码（且可配置用完擦除）。
 */
class MethodExtractor(private val logger: Logger) {

    companion object {
        /** 加密 blob 魔数 */
        const val METHOD_MAGIC = 0x48544D46  // "FMTH"

        /** 保护方法数上限（防止 blob 过大影响启动速度） */
        const val MAX_METHODS = 5000
    }

    /** 被保护方法的元信息 */
    data class ExtractedMethod(
        val methodIdx: Int,       // method_id 索引
        val codeOffset: Int,      // code_item 在 DEX 中的偏移
        val originalInsns: ByteArray,  // 原始字节码
        val registersSize: Int,   // 寄存器数
        val insSize: Int,         // 输入参数寄存器数
        val outsSize: Int         // 调用输出寄存器数
    )

    /**
     * 执行函数抽取
     *
     * @param dexData 原始 DEX 数据
     * @param key     AES 密钥（32 字节）
     * @return Pair<替换stub后的DEX, 加密的方法体blob>
     */
    fun extract(dexData: ByteArray, key: ByteArray): Pair<ByteArray, ByteArray> {
        // 1. 解析 DEX
        val parser = DexParser(dexData)
        parser.parse()

        logger.lifecycle("    DEX size: ${dexData.size} bytes")
        logger.lifecycle("    total methods: ${parser.methodIds.size}")
        logger.lifecycle("    code items: ${parser.codeItems.size}")

        // 2. 选择要保护的方法
        val candidates = parser.methodCodeMap.keys.filter { parser.isMethodProtected(it) }.sorted()
        val toProtect = if (candidates.size <= MAX_METHODS) candidates
        else candidates.sortedByDescending { idx ->
            parser.codeItems[parser.methodCodeMap[idx]]!!.insnsSize
        }.take(MAX_METHODS).sorted()

        logger.lifecycle("    methods to protect: ${toProtect.size}")

        if (toProtect.isEmpty()) {
            return dexData to ByteArray(0)
        }

        // 3. 提取方法体
        val extracted = toProtect.map { idx ->
            val codeOff = parser.methodCodeMap[idx]!!
            val code = parser.codeItems[codeOff]!!
            ExtractedMethod(
                methodIdx = idx,
                codeOffset = codeOff,
                originalInsns = code.insns.copyOf(),
                registersSize = code.registersSize,
                insSize = code.insSize,
                outsSize = code.outsSize
            )
        }

        // 4. 构建加密 blob
        val blob = buildEncryptedBlob(extracted, key)

        // 5. 替换 DEX 中的方法体为 stub
        val newDex = replaceMethodBodies(dexData, parser, extracted)

        logger.lifecycle("    encrypted methods blob: ${blob.size} bytes")
        logger.lifecycle("    new DEX: ${newDex.size} bytes")

        return newDex to blob
    }

    /**
     * 构建加密的方法体 blob
     *
     * 格式：
     *   头部 (16 bytes):
     *     magic(4) + version(4) + method_count(4) + index_size(4)
     *   索引表 (method_count * 16 bytes):
     *     [method_idx(4) + body_offset(4) + body_size(4) + meta(4)] * count
     *   加密数据:
     *     iv(16) + AES-CBC 加密后的方法体拼接 + SHA-256(32)
     */
    private fun buildEncryptedBlob(methods: List<ExtractedMethod>, key: ByteArray): ByteArray {
        // 构建索引表
        val indexStream = ByteArrayOutputStream()
        val indexDos = DataOutputStream(indexStream)

        // 构建方法体明文（所有方法体顺序拼接）
        val bodyStream = ByteArrayOutputStream()
        var bodyOffset = 0

        for (m in methods) {
            // 索引条目
            indexDos.writeInt(m.methodIdx)
            indexDos.writeInt(bodyOffset)
            indexDos.writeInt(m.originalInsns.size)
            // meta: 高 16 位 = registersSize, 低 16 位 = insSize
            indexDos.writeInt((m.registersSize shl 16) or (m.insSize and 0xFFFF))

            // 方法体数据
            bodyStream.write(m.originalInsns)
            bodyOffset += m.originalInsns.size
        }

        val indexData = indexStream.toByteArray()
        val bodyPlain = bodyStream.toByteArray()

        // AES-CBC 加密方法体
        val encrypted = AesCipher.encrypt(bodyPlain, key)
        // encrypted 格式: iv(16) + ciphertext

        // 计算明文 SHA-256（完整性校验）
        val sha = AesCipher.sha256(bodyPlain)

        // 组装完整 blob
        val header = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN)
            .putInt(METHOD_MAGIC)
            .putInt(1)  // version
            .putInt(methods.size)
            .putInt(indexData.size)
            .array()

        return header + indexData + encrypted + sha
    }

    /**
     * 替换 DEX 中的方法体为 stub 字节码
     *
     * stub 逻辑：
     *   return-void   (0x000e)
     *
     * 这是最简单的 stub，适用于所有返回 void 的方法。
     * 对于有返回值的方法，运行时 native 层会在调用前还原真实方法体，
     * 所以 stub 的 return 类型不匹配也没关系。
     */
    private fun replaceMethodBodies(
        dexData: ByteArray,
        parser: DexParser,
        methods: List<ExtractedMethod>
    ): ByteArray {
        val result = dexData.copyOf()

        // return-void 的 Dalvik 字节码（2 字节）
        val stubInsns = byteArrayOf(0x0e, 0x00)

        for (m in methods) {
            val code = parser.codeItems[m.codeOffset] ?: continue
            val insnsStart = m.codeOffset + 16  // code_item header 占 16 字节

            // 用 stub 覆盖原始字节码
            System.arraycopy(stubInsns, 0, result, insnsStart, stubInsns.size)

            // 剩余部分填充 NOP（0x0000）
            for (i in stubInsns.size until code.insns.size) {
                result[insnsStart + i] = 0
            }
        }

        return result
    }
}
