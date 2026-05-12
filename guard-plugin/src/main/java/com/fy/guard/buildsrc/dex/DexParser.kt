package com.fy.guard.buildsrc.dex

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * DEX 文件格式完整解析器
 *
 * 参考文档: https://source.android.com/docs/core/runtime/dex-format
 *
 * DEX 文件结构概览:
 *   header_item          (0x70 bytes)
 *   string_id_item[]     (每个 4 bytes)
 *   type_id_item[]       (每个 4 bytes)
 *   proto_id_item[]      (每个 12 bytes)
 *   field_id_item[]      (每个 8 bytes)
 *   method_id_item[]     (每个 8 bytes)
 *   class_def_item[]     (每个 32 bytes)
 *   data section         (包含 class_data_item 和 code_item 等)
 *
 * 本解析器的核心目标：
 *   建立 method_id_index → code_item 的完整映射，
 *   这是函数抽取的前提。
 */
class DexParser(val data: ByteArray) {

    private val buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)

    // ========== 数据类定义 ==========

    /** DEX 文件头（关键字段） */
    data class Header(
        val fileSize: Int,
        val stringIdsSize: Int, val stringIdsOff: Int,
        val typeIdsSize: Int, val typeIdsOff: Int,
        val protoIdsSize: Int, val protoIdsOff: Int,
        val fieldIdsSize: Int, val fieldIdsOff: Int,
        val methodIdsSize: Int, val methodIdsOff: Int,
        val classDefsSize: Int, val classDefsOff: Int,
        val mapOff: Int
    )

    /** method_id_item: 方法标识 */
    data class MethodId(
        val classIdx: Int,   // 所属类（type_id 索引）
        val protoIdx: Int,   // 方法原型（proto_id 索引）
        val nameIdx: Int     // 方法名（string_id 索引）
    )

    /** class_def_item: 类定义 */
    data class ClassDef(
        val classIdx: Int,       // 类类型索引
        val accessFlags: Int,    // 访问标志
        val classDataOff: Int    // class_data_item 偏移（包含方法列表）
    )

    /** code_item: 方法的字节码 */
    data class CodeItem(
        val offset: Int,          // 在 DEX 文件中的偏移
        val registersSize: Int,   // 使用的寄存器数量
        val insSize: Int,         // 输入参数占用的寄存器数
        val outsSize: Int,        // 调用其他方法时使用的寄存器数
        val triesSize: Int,       // try-catch 块数量
        val insnsSize: Int,       // 字节码大小（2 字节为单位）
        val insns: ByteArray      // 原始 Dalvik 字节码
    ) {
        /** code_item 在文件中占用的总字节数 */
        val totalSize: Int
            get() {
                var size = 16 + insnsSize * 2  // header(16) + insns
                if (triesSize > 0 && insnsSize % 2 != 0) size += 2  // padding
                size += triesSize * 8  // try_item 数组
                return size
            }
    }

    // ========== 解析结果 ==========

    lateinit var header: Header; private set
    lateinit var stringIds: IntArray; private set
    lateinit var typeIds: IntArray; private set
    lateinit var methodIds: Array<MethodId>; private set
    lateinit var classDefs: Array<ClassDef>; private set

    /**
     * 所有已解析的 code_item
     * key: code_item 在 DEX 文件中的偏移
     */
    val codeItems = mutableMapOf<Int, CodeItem>()

    /**
     * 方法索引 → code_item 偏移的映射
     * key: method_id 索引
     * value: 对应 code_item 的文件偏移
     *
     * 这是函数抽取的核心数据结构：
     * 通过 method_id 找到对应的 code_item，即可提取/替换方法体
     */
    val methodCodeMap = mutableMapOf<Int, Int>()

    // ========== LEB128 解码 ==========

    /**
     * 读取无符号 LEB128 编码的整数
     * DEX 中大量使用 LEB128 编码来节省空间
     *
     * @param pos 起始偏移
     * @return Pair(解码值, 新偏移)
     */
    private fun readULEB128(pos: Int): Pair<Long, Int> {
        var result = 0L
        var shift = 0
        var p = pos
        while (true) {
            val b = data[p].toInt() and 0xFF
            p++
            result = result or ((b and 0x7F).toLong() shl shift)
            if (b and 0x80 == 0) break
            shift += 7
        }
        return result to p
    }

    // ========== 主解析流程 ==========

    /**
     * 解析整个 DEX 文件
     * 按顺序解析各个 section，最终建立 method → code_item 映射
     */
    fun parse() {
        parseHeader()
        parseStringIds()
        parseTypeIds()
        parseMethodIds()
        parseClassDefs()
        parseAllCodeItems()  // 最关键：遍历所有 class_data_item，建立映射
    }

    private fun parseHeader() {
        header = Header(
            fileSize = buf.getInt(32),
            stringIdsSize = buf.getInt(56), stringIdsOff = buf.getInt(60),
            typeIdsSize = buf.getInt(64), typeIdsOff = buf.getInt(68),
            protoIdsSize = buf.getInt(72), protoIdsOff = buf.getInt(76),
            fieldIdsSize = buf.getInt(80), fieldIdsOff = buf.getInt(84),
            methodIdsSize = buf.getInt(88), methodIdsOff = buf.getInt(92),
            classDefsSize = buf.getInt(96), classDefsOff = buf.getInt(100),
            mapOff = buf.getInt(52)
        )
    }

    private fun parseStringIds() {
        stringIds = IntArray(header.stringIdsSize) {
            buf.getInt(header.stringIdsOff + it * 4)
        }
    }

    private fun parseTypeIds() {
        typeIds = IntArray(header.typeIdsSize) {
            buf.getInt(header.typeIdsOff + it * 4)
        }
    }

    private fun parseMethodIds() {
        methodIds = Array(header.methodIdsSize) {
            buf.position(header.methodIdsOff + it * 8)
            MethodId(
                classIdx = buf.short.toInt() and 0xFFFF,
                protoIdx = buf.short.toInt() and 0xFFFF,
                nameIdx = buf.int
            )
        }
    }

    private fun parseClassDefs() {
        classDefs = Array(header.classDefsSize) {
            buf.position(header.classDefsOff + it * 32)
            ClassDef(
                classIdx = buf.int,
                accessFlags = buf.int,
                classDataOff = buf.int  // 只关心 classDataOff，跳过其他字段
            ).also {
                // 跳过剩余字段
                buf.int; buf.int; buf.int; buf.int
            }
        }
    }

    /**
     * 解析所有 class_data_item，建立 method_id → code_item 映射
     *
     * class_data_item 结构:
     *   static_fields_size    (ULEB128)
     *   instance_fields_size  (ULEB128)
     *   direct_methods_size   (ULEB128)
     *   virtual_methods_size  (ULEB128)
     *   fields[]              (static + instance)
     *   methods[]             (direct + virtual)
     *     - method_idx_diff   (ULEB128)  ← 差分编码的方法索引
     *     - access_flags      (ULEB128)
     *     - code_off          (ULEB128)  ← code_item 偏移，0 表示 abstract/native
     */
    private fun parseAllCodeItems() {
        for (classDef in classDefs) {
            if (classDef.classDataOff == 0) continue  // 接口/抽象类可能没有 class_data
            parseClassData(classDef.classDataOff)
        }
    }

    private fun parseClassData(off: Int) {
        var pos = off

        // 读取字段和方法计数
        val (staticFieldsSize, p1) = readULEB128(pos); pos = p1
        val (instanceFieldsSize, p2) = readULEB128(pos); pos = p2
        val (directMethodsSize, p3) = readULEB128(pos); pos = p3
        val (virtualMethodsSize, p4) = readULEB128(pos); pos = p4

        // 跳过所有字段条目
        val totalFields = (staticFieldsSize + instanceFieldsSize).toInt()
        for (i in 0 until totalFields) {
            val (_, p5) = readULEB128(pos); pos = p5  // field_idx_diff
            val (_, p6) = readULEB128(pos); pos = p6  // access_flags
        }

        // 解析所有方法条目
        val totalMethods = (directMethodsSize + virtualMethodsSize).toInt()
        var prevMethodIdx = 0L  // 差分编码的累计器

        for (i in 0 until totalMethods) {
            val (methodIdxDiff, p7) = readULEB128(pos); pos = p7
            val (_, p8) = readULEB128(pos); pos = p8  // access_flags
            val (codeOff, p9) = readULEB128(pos); pos = p9

            // 还原实际的 method_id 索引
            val methodIdx = (prevMethodIdx + methodIdxDiff).toInt()
            prevMethodIdx += methodIdxDiff

            // 如果有 code_item，解析并记录映射
            if (codeOff != 0L) {
                val codeItem = parseCodeItem(codeOff.toInt())
                if (codeItem != null) {
                    codeItems[codeOff.toInt()] = codeItem
                    methodCodeMap[methodIdx] = codeOff.toInt()
                }
            }
        }
    }

    /**
     * 解析单个 code_item
     *
     * code_item 结构:
     *   registers_size (u16) - 该方法使用的寄存器总数
     *   ins_size       (u16) - 输入参数占用的寄存器数
     *   outs_size      (u16) - 调用其他方法时占用的寄存器数
     *   tries_size     (u16) - try 块数量
     *   debug_info_off (u32) - 调试信息偏移
     *   insns_size     (u32) - 字节码大小（以 2 字节为单位）
     *   insns[]              - 实际的 Dalvik 字节码
     *   [padding]            - tries_size > 0 时可能需要 2 字节对齐
     *   try_item[]           - try 块信息
     */
    private fun parseCodeItem(off: Int): CodeItem? {
        if (off + 16 > data.size) return null

        buf.position(off)
        val registersSize = buf.short.toInt() and 0xFFFF
        val insSize = buf.short.toInt() and 0xFFFF
        val outsSize = buf.short.toInt() and 0xFFFF
        val triesSize = buf.short.toInt() and 0xFFFF
        buf.int  // debug_info_off
        val insnsSize = buf.int  // 以 2 字节为单位

        // 边界检查
        if (insnsSize < 0 || off + 16 + insnsSize * 2 > data.size) return null

        // 提取字节码数据
        val insns = data.copyOfRange(off + 16, off + 16 + insnsSize * 2)

        return CodeItem(
            offset = off,
            registersSize = registersSize,
            insSize = insSize,
            outsSize = outsSize,
            triesSize = triesSize,
            insnsSize = insnsSize,
            insns = insns
        )
    }

    // ========== 工具方法 ==========

    /**
     * 从 string_id 索引获取字符串内容
     */
    fun getString(idx: Int): String {
        val strOff = stringIds[idx]
        val (strLen, strStart) = readULEB128(strOff)
        return String(data, strStart, strLen.toInt(), Charsets.UTF_8)
    }

    /**
     * 获取方法名
     */
    fun getMethodName(idx: Int): String {
        return getString(methodIds[idx].nameIdx)
    }

    /**
     * 获取方法的完整签名（类名->方法名）
     */
    fun getMethodSignature(idx: Int): String {
        val m = methodIds[idx]
        val className = getString(typeIds[m.classIdx])
        val methodName = getString(m.nameIdx)
        return "$className->$methodName"
    }

    /**
     * 判断方法是否适合被保护
     *
     * 排除以下方法：
     * - <init> 和 <clinit>（构造器和静态初始化器）
     * - abstract 和 native 方法（没有 code_item）
     * - 过短的方法（字节码 < 4 条指令）
     */
    fun isMethodProtected(idx: Int): Boolean {
        val name = getMethodName(idx)
        // 排除构造器
        if (name == "<init>" || name == "<clinit>") return false

        // 检查是否有 code_item
        val codeOff = methodCodeMap[idx] ?: return false
        val code = codeItems[codeOff] ?: return false

        // 排除过短的方法（保护价值低，stub 开销反而大）
        return code.insnsSize >= 4
    }
}
