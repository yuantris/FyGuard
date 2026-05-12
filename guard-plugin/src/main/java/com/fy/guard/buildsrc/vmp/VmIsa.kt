package com.fy.guard.buildsrc.vmp

/**
 * VMP 虚拟机指令集定义
 *
 * 设计原则：
 *   1. 寄存器架构 —— 与 Dalvik 一致，降低翻译复杂度
 *   2. 足够覆盖常见 Dalvik 操作 —— 算术、比较、分支、调用
 *   3. 每个方法使用独立的 opcode 映射 —— 增加逆向难度
 *   4. 支持不透明谓词和垃圾指令 —— 混淆控制流
 *
 * 所有操作码值都是逻辑值。
 * 实际编码时通过 generateOpcodeMap() 进行随机映射。
 * 同一个方法每次构建使用不同的映射（基于方法索引的种子）。
 */
object VmIsa {

    // ========== 基础操作 ==========
    const val OP_NOP     = 0x00  // 空操作
    const val OP_MOVE    = 0x01  // vA = vB
    const val OP_CONST_W = 0x03  // vA = #+BBBBBBBB (32 位常量)
    const val OP_CONST_L = 0x04  // vA = #+BBBBBBBBBBBBBBBB (64 位常量)
    const val OP_CONST_S = 0x05  // vA = #+BB (8 位有符号常量)

    // ========== 算术运算 ==========
    const val OP_ADD  = 0x10  // vA = vB + vC
    const val OP_SUB  = 0x11  // vA = vB - vC
    const val OP_MUL  = 0x12  // vA = vB * vC
    const val OP_DIV  = 0x13  // vA = vB / vC
    const val OP_REM  = 0x14  // vA = vB % vC
    const val OP_AND  = 0x15  // vA = vB & vC
    const val OP_OR   = 0x16  // vA = vB | vC
    const val OP_XOR  = 0x17  // vA = vB ^ vC
    const val OP_SHL  = 0x18  // vA = vB << vC
    const val OP_SHR  = 0x19  // vA = vB >> vC (算术右移)
    const val OP_USHR = 0x1A  // vA = vB >>> vC (逻辑右移)
    const val OP_NEG  = 0x1B  // vA = -vB
    const val OP_NOT  = 0x1D  // vA = ~vB

    // ========== 比较运算 ==========
    const val OP_CMP  = 0x30  // vA = cmp(vB, vC)

    // ========== 条件分支 ==========
    const val OP_IF_EQ  = 0x40  // if (vA == vB) goto +CC
    const val OP_IF_NE  = 0x41  // if (vA != vB) goto +CC
    const val OP_IF_LT  = 0x42  // if (vA < vB) goto +CC
    const val OP_IF_GE  = 0x43  // if (vA >= vB) goto +CC
    const val OP_IF_GT  = 0x44  // if (vA > vB) goto +CC
    const val OP_IF_LE  = 0x45  // if (vA <= vB) goto +CC
    const val OP_IF_EQZ = 0x46  // if (vA == 0) goto +BB
    const val OP_IF_NEZ = 0x47  // if (vA != 0) goto +BB
    const val OP_IF_LTZ = 0x48  // if (vA < 0) goto +BB
    const val OP_IF_GEZ = 0x49  // if (vA >= 0) goto +BB
    const val OP_IF_GTZ = 0x4A  // if (vA > 0) goto +BB
    const val OP_IF_LEZ = 0x4B  // if (vA <= 0) goto +BB

    // ========== 无条件跳转 ==========
    const val OP_GOTO  = 0x50  // goto +BB

    // ========== 方法调用 ==========
    const val OP_INVOKE = 0x70  // invoke method, {vA..vC}

    // ========== 对象操作 ==========
    const val OP_NEW    = 0x80  // vA = new Type

    // ========== 返回 ==========
    const val OP_RETURN_V = 0xA0  // return-void
    const val OP_RETURN   = 0xA1  // return vA

    // ========== 混淆 ==========
    const val OP_JUNK  = 0xFE  // 垃圾指令（执行时被忽略）
    const val OP_HALT  = 0xFF  // VM 停机

    /**
     * VM 指令结构
     *
     * @param op  操作码（逻辑值，编码时需经过映射表转换）
     * @param ops 操作数数组（最多 8 个）
     */
    data class Insn(val op: Int, val ops: IntArray = intArrayOf()) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Insn) return false
            return op == other.op && ops.contentEquals(other.ops)
        }
        override fun hashCode(): Int = 31 * op + ops.contentHashCode()
    }

    /**
     * 生成随机 opcode 映射表
     *
     * 将逻辑 opcode 映射到实际编码值。
     * 基于种子的 Fisher-Yates 洗牌，确保可重现。
     *
     * 每个被保护的方法使用不同的种子（基于 method_idx），
     * 逆向时无法用一个映射表解码所有方法。
     *
     * @param seed 随机种子
     * @return 256 个元素的映射表 [logical_op → encoded_op]
     */
    fun generateOpcodeMap(seed: Long): IntArray {
        val rng = java.util.Random(seed)
        return IntArray(256) { it }.also { arr ->
            for (i in 255 downTo 1) {
                val j = rng.nextInt(i + 1)
                val tmp = arr[i]; arr[i] = arr[j]; arr[j] = tmp
            }
        }
    }

    /**
     * 生成逆映射表（用于解码）
     *
     * @param map 正向映射表 [logical → encoded]
     * @return 逆向映射表 [encoded → logical]
     */
    fun generateInverseMap(map: IntArray): IntArray {
        val inv = IntArray(256)
        for (i in map.indices) inv[map[i]] = i
        return inv
    }

    /**
     * 构建不透明谓词（Opaque Predicate）
     *
     * 不透明谓词是恒真/恒假的条件分支，
     * 插入后能有效干扰控制流分析工具（如 IDA 的 Hex-Rays）。
     *
     * 恒真谓词示例: (x * x) >= 0  → 对于任意整数 x 恒为真
     *
     * @param reg 起始寄存器号
     * @return 插入的指令序列
     */
    fun buildOpaquePredicate(reg: Int): List<Insn> = listOf(
        // v[reg+1] = v[reg] * v[reg]  （平方）
        Insn(OP_MUL, intArrayOf(reg + 1, reg, reg)),
        // if (v[reg+1] >= 0) goto +2  （恒真，总是跳转）
        Insn(OP_IF_GEZ, intArrayOf(reg + 1, 2)),
        // 垃圾路径（永远不会执行）
        Insn(OP_HALT)
    )
}
