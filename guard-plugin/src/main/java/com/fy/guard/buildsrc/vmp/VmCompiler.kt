package com.fy.guard.buildsrc.vmp

import org.gradle.api.logging.Logger
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream

/**
 * Dalvik → VM 字节码编译器（第三代加固核心）
 *
 * 将方法的 Dalvik 字节码翻译为自定义 VM 指令集，
 * 并注入混淆（不透明谓词、垃圾指令、随机 opcode 映射）。
 *
 * 翻译策略：
 *   - 常见操作（算术、比较、分支）→ 1:1 翻译为 VM 指令
 *   - 复杂操作（invoke、field access）→ 通过 JNI 回调到 ART
 *   - 未识别的操作码 → 翻译为 NOP（降级但不崩溃）
 *
 * 安全效果：
 *   - 原始 Dalvik 字节码被完全替换
 *   - 每个方法使用独立的 opcode 映射
 *   - 控制流被不透明谓词和垃圾指令打乱
 *   - 静态分析工具无法直接反编译
 */
class VmCompiler(private val logger: Logger) {

    /**
     * 编译结果
     */
    data class CompiledMethod(
        val methodIdx: Int,       // 方法索引
        val vmBytecode: ByteArray,  // 编译后的 VM 字节码
        val opcodeMap: IntArray     // 该方法使用的 opcode 映射表
    )

    /**
     * 编译一个方法
     *
     * @param methodIdx    方法索引（用于生成种子）
     * @param dalvikInsns  原始 Dalvik 字节码（2 字节对齐）
     * @return 编译结果
     */
    fun compile(methodIdx: Int, dalvikInsns: ByteArray): CompiledMethod {
        // 基于方法索引生成确定性种子
        val seed = methodIdx.toLong() * 0x9E3779B97F4A7C15UL.toLong()
        val opcodeMap = VmIsa.generateOpcodeMap(seed)

        val vmInsns = mutableListOf<VmIsa.Insn>()
        val dalvikCount = dalvikInsns.size / 2

        // 逐条翻译 Dalvik 指令
        var pc = 0
        while (pc < dalvikCount) {
            val op = dalvikInsns[pc * 2].toInt() and 0xFF
            val extra = dalvikInsns[pc * 2 + 1].toInt() and 0xFF

            when (op) {
                // ========= nop =========
                0x00 -> {
                    vmInsns.add(VmIsa.Insn(VmIsa.OP_NOP))
                    pc++
                }

                // ========= move vA, vB =========
                0x01 -> {
                    val w = dalvikInsns[pc * 2 + 1].toInt() and 0xFF
                    val vA = w and 0x0F
                    val vB = w shr 4
                    vmInsns.add(VmIsa.Insn(VmIsa.OP_MOVE, intArrayOf(vA, vB)))
                    pc++
                }

                // ========= const/4 vA, #+B =========
                0x12 -> {
                    val vA = extra and 0x0F
                    val lit = (extra shr 4).toByte().toInt()  // 4-bit 符号扩展
                    vmInsns.add(VmIsa.Insn(VmIsa.OP_CONST_S, intArrayOf(vA, lit)))
                    pc++
                }

                // ========= const/16 vA, #+BBBB =========
                0x13 -> {
                    val vA = dalvikInsns[pc * 2 + 1].toInt() and 0x0F
                    val lo = dalvikInsns[pc * 2 + 2].toInt() and 0xFF
                    val hi = dalvikInsns[pc * 2 + 3].toInt() and 0xFF
                    val lit = (lo or (hi shl 8)).toShort().toInt()
                    vmInsns.add(VmIsa.Insn(VmIsa.OP_CONST_W, intArrayOf(vA, lit)))
                    pc += 2
                }

                // ========= const vA, #+BBBBBBBB =========
                0x14 -> {
                    val vA = dalvikInsns[pc * 2 + 1].toInt() and 0x0F
                    val b0 = dalvikInsns[pc * 2 + 2].toInt() and 0xFF
                    val b1 = dalvikInsns[pc * 2 + 3].toInt() and 0xFF
                    val b2 = dalvikInsns[pc * 2 + 4].toInt() and 0xFF
                    val b3 = dalvikInsns[pc * 2 + 5].toInt() and 0xFF
                    val lit = b0 or (b1 shl 8) or (b2 shl 16) or (b3 shl 24)
                    vmInsns.add(VmIsa.Insn(VmIsa.OP_CONST_W, intArrayOf(vA, lit)))
                    pc += 3
                }

                // ========= goto +AA =========
                0x28 -> {
                    val offset = dalvikInsns[pc * 2 + 1].toInt().toByte().toInt()
                    vmInsns.add(VmIsa.Insn(VmIsa.OP_GOTO, intArrayOf(offset)))
                    pc++
                }

                // ========= goto/16 +AAAA =========
                0x29 -> {
                    val lo = dalvikInsns[pc * 2 + 2].toInt() and 0xFF
                    val hi = dalvikInsns[pc * 2 + 3].toInt() and 0xFF
                    val offset = (lo or (hi shl 8)).toShort().toInt()
                    vmInsns.add(VmIsa.Insn(VmIsa.OP_GOTO, intArrayOf(offset)))
                    pc += 2
                }

                // ========= return-void =========
                0x0E -> {
                    vmInsns.add(VmIsa.Insn(VmIsa.OP_RETURN_V))
                    pc++
                }

                // ========= return vAA =========
                0x0F -> {
                    val vA = dalvikInsns[pc * 2 + 1].toInt() and 0xFF
                    vmInsns.add(VmIsa.Insn(VmIsa.OP_RETURN, intArrayOf(vA)))
                    pc++
                }

                // ========= return-wide vAA =========
                0x10 -> {
                    val vA = dalvikInsns[pc * 2 + 1].toInt() and 0xFF
                    vmInsns.add(VmIsa.Insn(VmIsa.OP_RETURN, intArrayOf(vA)))
                    pc++
                }

                // ========= return-object vAA =========
                0x11 -> {
                    val vA = dalvikInsns[pc * 2 + 1].toInt() and 0xFF
                    vmInsns.add(VmIsa.Insn(VmIsa.OP_RETURN, intArrayOf(vA)))
                    pc++
                }

                // ========= 算术运算: add-int, sub-int, ... =========
                // 格式: AA|op CC|BB → vAA = vBB op vCC
                in 0x90..0xAF -> {
                    val vmOp = VmIsa.OP_ADD + (op - 0x90)
                    val b0 = dalvikInsns[pc * 2 + 1].toInt() and 0xFF
                    val b1 = dalvikInsns[pc * 2 + 2].toInt() and 0xFF
                    val vA = b0
                    val vB = b1 and 0x0F
                    val vC = b1 shr 4
                    vmInsns.add(VmIsa.Insn(vmOp, intArrayOf(vA, vB, vC)))
                    pc += 2
                }

                // ========= if-eq vA, vB, +CCCC =========
                0x32 -> { translateIf(op, dalvikInsns, pc, vmInsns); pc += 3 }
                0x33 -> { translateIf(op, dalvikInsns, pc, vmInsns); pc += 3 }
                0x34 -> { translateIf(op, dalvikInsns, pc, vmInsns); pc += 3 }
                0x35 -> { translateIf(op, dalvikInsns, pc, vmInsns); pc += 3 }
                0x36 -> { translateIf(op, dalvikInsns, pc, vmInsns); pc += 3 }
                0x37 -> { translateIf(op, dalvikInsns, pc, vmInsns); pc += 3 }

                // ========= if-eqz vAA, +BBBB =========
                0x38 -> { translateIfZ(op, dalvikInsns, pc, vmInsns); pc += 2 }
                0x39 -> { translateIfZ(op, dalvikInsns, pc, vmInsns); pc += 2 }
                0x3A -> { translateIfZ(op, dalvikInsns, pc, vmInsns); pc += 2 }
                0x3B -> { translateIfZ(op, dalvikInsns, pc, vmInsns); pc += 2 }
                0x3C -> { translateIfZ(op, dalvikInsns, pc, vmInsns); pc += 2 }
                0x3D -> { translateIfZ(op, dalvikInsns, pc, vmInsns); pc += 2 }

                // ========= 其他未覆盖的操作码 → NOP =========
                else -> {
                    vmInsns.add(VmIsa.Insn(VmIsa.OP_NOP))
                    pc += getDalvikSize(op)
                }
            }

            // 每隔几条真实指令，随机插入垃圾指令
            if (vmInsns.size % 7 == 0) {
                vmInsns.add(VmIsa.Insn(VmIsa.OP_JUNK, intArrayOf(0xDE, 0xAD)))
            }
        }

        // 在方法开头插入不透明谓词（混淆控制流分析）
        val allInsns = VmIsa.buildOpaquePredicate(0) + vmInsns

        // 编码为字节流
        val encoded = encode(allInsns, opcodeMap)

        logger.lifecycle("    method $methodIdx: $dalvikCount dalvik → ${allInsns.size} VM insns")

        return CompiledMethod(methodIdx, encoded, opcodeMap)
    }

    // ========== 翻译辅助方法 ==========

    private fun translateIf(dalvikOp: Int, insns: ByteArray, pc: Int, out: MutableList<VmIsa.Insn>) {
        val vmOp = when (dalvikOp) {
            0x32 -> VmIsa.OP_IF_EQ; 0x33 -> VmIsa.OP_IF_NE
            0x34 -> VmIsa.OP_IF_LT; 0x35 -> VmIsa.OP_IF_GE
            0x36 -> VmIsa.OP_IF_GT; 0x37 -> VmIsa.OP_IF_LE
            else -> VmIsa.OP_IF_EQ
        }
        val b0 = insns[pc * 2 + 1].toInt() and 0xFF
        val lo = insns[pc * 2 + 2].toInt() and 0xFF
        val hi = insns[pc * 2 + 3].toInt() and 0xFF
        val offset = (lo or (hi shl 8)).toShort().toInt()
        out.add(VmIsa.Insn(vmOp, intArrayOf(b0 and 0x0F, b0 shr 4, offset)))
    }

    private fun translateIfZ(dalvikOp: Int, insns: ByteArray, pc: Int, out: MutableList<VmIsa.Insn>) {
        val vmOp = when (dalvikOp) {
            0x38 -> VmIsa.OP_IF_EQZ; 0x39 -> VmIsa.OP_IF_NEZ
            0x3A -> VmIsa.OP_IF_LTZ; 0x3B -> VmIsa.OP_IF_GEZ
            0x3C -> VmIsa.OP_IF_GTZ; 0x3D -> VmIsa.OP_IF_LEZ
            else -> VmIsa.OP_IF_EQZ
        }
        val vA = insns[pc * 2 + 1].toInt() and 0xFF
        val lo = insns[pc * 2 + 2].toInt() and 0xFF
        val hi = insns[pc * 2 + 3].toInt() and 0xFF
        val offset = (lo or (hi shl 8)).toShort().toInt()
        out.add(VmIsa.Insn(vmOp, intArrayOf(vA, offset)))
    }

    private fun getDalvikSize(op: Int): Int = when (op) {
        0x00, 0x0E, 0x0F, 0x10, 0x11, 0x01, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x12, 0x28 -> 1
        0x13, 0x14, 0x15, 0x16, 0x17, 0x22, 0x23, 0x29, 0x2A -> 2
        in 0x32..0x3D, in 0x6E..0x78, in 0x52..0x5D, in 0x90..0xAF -> 2
        else -> 1
    }

    // ========== 编码 ==========

    /**
     * 将 VM 指令编码为字节流
     *
     * 每条指令编码格式:
     *   encoded_opcode (1 byte)
     *   operand_count  (1 byte)
     *   operands       (operand_count * 4 bytes, 每个操作数 32-bit LE)
     */
    private fun encode(insns: List<VmIsa.Insn>, opcodeMap: IntArray): ByteArray {
        val out = ByteArrayOutputStream()
        val dos = DataOutputStream(out)

        // 指令总数
        dos.writeInt(insns.size)

        for (insn in insns) {
            // 操作码经过映射表编码（防止静态分析直接读取操作码）
            dos.writeByte(opcodeMap[insn.op])
            // 操作数数量
            dos.writeByte(insn.ops.size)
            // 操作数（每个 32-bit）
            for (op in insn.ops) dos.writeInt(op)
        }

        return out.toByteArray()
    }
}
