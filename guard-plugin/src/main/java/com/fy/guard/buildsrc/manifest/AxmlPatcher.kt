package com.fy.guard.buildsrc.manifest

import org.gradle.api.logging.Logger
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Binary AXML StringPool patcher (reference: AndResGuard StringChunk)
 *
 * Directly modifies the binary AXML bytes of AndroidManifest.xml in an APK,
 * replacing strings in the StringPool without aapt2 recompilation.
 */
class AxmlPatcher(private val logger: Logger) {

    data class PatchResult(
        val success: Boolean,
        val originalAppClass: String,
        val message: String
    )

    fun patchApplicationName(
        manifestFile: File,
        newAppName: String
    ): PatchResult {
        if (!manifestFile.exists()) {
            return PatchResult(false, "", "Manifest not found: ${manifestFile.path}")
        }
        val bytes = manifestFile.readBytes()
        if (bytes.size < 8 || readInt16(bytes, 0) != 0x0003 || readInt16(bytes, 2) != 0x0008) {
            return PatchResult(false, "", "Not a valid AXML file")
        }
        logger.lifecycle("    [AxmlPatcher] AXML size: ${bytes.size} bytes")
        val sp = parseStringPool(bytes)
            ?: return PatchResult(false, "", "Failed to parse StringPool")
        logger.lifecycle("    [AxmlPatcher] StringPool: ${sp.stringCount} strings, " +
                "UTF-${if (sp.isUtf8) "8" else "16"}, chunkSize=${sp.chunkSize}")
        val appClassIndex = findApplicationClassName(sp)
        if (appClassIndex < 0) {
            return PatchResult(false, "", "Application class name not found in StringPool")
        }
        val originalAppClass = sp.strings[appClassIndex]
        logger.lifecycle("    [AxmlPatcher] found app class: index=$appClassIndex, value='$originalAppClass'")
        if (originalAppClass == newAppName) {
            logger.lifecycle("    [AxmlPatcher] already patched, skipping")
            return PatchResult(true, originalAppClass, "Already patched")
        }
        sp.strings[appClassIndex] = newAppName
        logger.lifecycle("    [AxmlPatcher] replaced: '$originalAppClass' -> '$newAppName'")
        val newSpBytes = buildStringPool(sp)
        val spOffset = 8
        val result = ByteArray(spOffset + newSpBytes.size + (bytes.size - spOffset - sp.chunkSize))
        System.arraycopy(bytes, 0, result, 0, spOffset)
        System.arraycopy(newSpBytes, 0, result, spOffset, newSpBytes.size)
        System.arraycopy(bytes, spOffset + sp.chunkSize, result,
            spOffset + newSpBytes.size, bytes.size - spOffset - sp.chunkSize)
        val newFileSize = result.size
        result[4] = (newFileSize and 0xFF).toByte()
        result[5] = ((newFileSize shr 8) and 0xFF).toByte()
        result[6] = ((newFileSize shr 16) and 0xFF).toByte()
        result[7] = ((newFileSize shr 24) and 0xFF).toByte()
        manifestFile.writeBytes(result)
        logger.lifecycle("    [AxmlPatcher] new AXML size: ${result.size} bytes")
        return PatchResult(true, originalAppClass, "Patched successfully")
    }

    // ===== StringPool parsing =====

    private data class StringPoolInfo(
        val chunkSize: Int,
        val stringCount: Int,
        val styleCount: Int,
        val flags: Int,
        val stringsOffset: Int,
        val stylesOffset: Int,
        val isUtf8: Boolean,
        val stringOffsets: IntArray,
        val strings: MutableList<String>,
        val rawStringBytes: ByteArray
    )

    private fun parseStringPool(axml: ByteArray): StringPoolInfo? {
        val spStart = 8
        if (axml.size < spStart + 16) return null
        val type = readInt16(axml, spStart)
        if (type != 0x0001) {
            logger.lifecycle("    [AxmlPatcher] expected StringPool type 0x0001, got 0x${type.toString(16)}")
            return null
        }
        val headerSize = readInt16(axml, spStart + 2)
        val chunkSize = readInt32(axml, spStart + 4)
        val stringCount = readInt32(axml, spStart + 8)
        val styleCount = readInt32(axml, spStart + 12)
        val flags = readInt32(axml, spStart + 16)
        val stringsOffset = readInt32(axml, spStart + 20)
        val stylesOffset = readInt32(axml, spStart + 24)
        val isUtf8 = (flags and 0x00000100) != 0
        val offsetsStart = spStart + headerSize
        val stringOffsets = IntArray(stringCount)
        for (i in 0 until stringCount) {
            stringOffsets[i] = readInt32(axml, offsetsStart + i * 4)
        }
        val stringsDataStart = spStart + stringsOffset
        val stringsDataEnd = if (styleCount > 0) spStart + stylesOffset else spStart + chunkSize
        val rawStringBytes = axml.copyOfRange(stringsDataStart, stringsDataEnd)
        val strings = mutableListOf<String>()
        for (i in 0 until stringCount) {
            val str = if (isUtf8) readUtf8String(rawStringBytes, stringOffsets[i])
            else readUtf16String(rawStringBytes, stringOffsets[i])
            strings.add(str)
        }
        return StringPoolInfo(chunkSize, stringCount, styleCount, flags,
            stringsOffset, stylesOffset, isUtf8, stringOffsets, strings, rawStringBytes)
    }

    private fun readUtf16String(data: ByteArray, offset: Int): String {
        if (offset >= data.size) return ""
        val charLen = readInt16(data, offset)
        if (charLen <= 0) return ""
        if (offset + 2 + charLen * 2 > data.size) return ""
        val chars = CharArray(charLen)
        for (i in 0 until charLen) {
            val bi = offset + 2 + i * 2
            chars[i] = ((data[bi].toInt() and 0xFF) or
                    ((data[bi + 1].toInt() and 0xFF) shl 8)).toChar()
        }
        return String(chars)
    }

    private fun readUtf8String(data: ByteArray, offset: Int): String {
        if (offset >= data.size) return ""
        var pos = offset
        val b0 = data[pos].toInt() and 0xFF; pos++
        val charLen = if (b0 and 0x80 != 0) ((b0 and 0x7F) shl 8) or (data[pos].toInt() and 0xFF)
        else b0; pos++
        val b2 = data[pos].toInt() and 0xFF; pos++
        val byteLen = if (b2 and 0x80 != 0) ((b2 and 0x7F) shl 8) or (data[pos].toInt() and 0xFF)
        else b2; pos++
        if (pos + byteLen > data.size) return ""
        return String(data, pos, byteLen, Charsets.UTF_8)
    }

    // ===== Find Application class name =====

    private fun findApplicationClassName(sp: StringPoolInfo): Int {
        for (i in sp.strings.indices) {
            val s = sp.strings[i]
            if (s.endsWith("Application") && s.contains(".")) return i
        }
        return -1
    }

    // ===== Rebuild StringPool (reference: AndResGuard StringChunk.getByte) =====

    private fun buildStringPool(sp: StringPoolInfo): ByteArray {
        val isUtf8 = sp.isUtf8
        val newCount = sp.strings.size
        val stringBytesList = mutableListOf<ByteArray>()
        var totalStringBytes = 0
        for (s in sp.strings) {
            val sb = if (isUtf8) encodeUtf8String(s) else encodeUtf16String(s)
            stringBytesList.add(sb)
            totalStringBytes += sb.size
        }
        val headerSize = 28
        val stringsOffset = headerSize + newCount * 4
        val rawChunkSize = stringsOffset + totalStringBytes
        val chunkSize = (rawChunkSize + 3) and 0x3.toInt().inv() // 4-byte align
        val buf = ByteBuffer.allocate(chunkSize).order(ByteOrder.LITTLE_ENDIAN)
        buf.putShort(0x0001)
        buf.putShort(headerSize.toShort())
        buf.putInt(chunkSize)
        buf.putInt(newCount)
        buf.putInt(0)
        buf.putInt(sp.flags)
        buf.putInt(stringsOffset)
        buf.putInt(chunkSize)
        var off = 0
        for (sb in stringBytesList) { buf.putInt(off); off += sb.size }
        for (sb in stringBytesList) { buf.put(sb) }
        return buf.array()
    }

    private fun encodeUtf16String(s: String): ByteArray {
        val buf = ByteBuffer.allocate(2 + s.length * 2 + 2).order(ByteOrder.LITTLE_ENDIAN)
        buf.putShort(s.length.toShort())
        for (c in s) buf.putShort(c.code.toShort())
        buf.putShort(0)
        return buf.array()
    }

    private fun encodeUtf8String(s: String): ByteArray {
        val bytes = s.toByteArray(Charsets.UTF_8)
        val buf = ByteBuffer.allocate(1 + 1 + bytes.size + 1).order(ByteOrder.LITTLE_ENDIAN)
        buf.put(bytes.size.toByte())
        buf.put(bytes.size.toByte())
        buf.put(bytes)
        buf.put(0)
        return buf.array()
    }

    // ===== Helpers =====

    private fun readInt16(data: ByteArray, offset: Int): Int =
        (data[offset].toInt() and 0xFF) or ((data[offset + 1].toInt() and 0xFF) shl 8)

    private fun readInt32(data: ByteArray, offset: Int): Int =
        (data[offset].toInt() and 0xFF) or ((data[offset + 1].toInt() and 0xFF) shl 8) or
                ((data[offset + 2].toInt() and 0xFF) shl 16) or ((data[offset + 3].toInt() and 0xFF) shl 24)
}
