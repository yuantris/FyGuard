//
// Created by 方方大王 on 2026/5/13.
//
/*
 * vm_engine.c — VMP 自定义字节码解释器
 *
 * 执行由 buildSrc VmCompiler 编译生成的自定义字节码。
 *
 * 指令集架构：
 *   - 寄存器式（与 Dalvik 一致）
 *   - 256 个 64-bit 寄存器（兼容 int/long/object）
 *   - 变长指令编码（1-3 个操作数，每个 32-bit）
 *   - 每个方法独立的 opcode 映射表（混淆用）
 *
 * 性能策略：
 *   - switch-based dispatch（可移植，兼容 ARM64 和 x86 模拟器）
 *   - 生产环境可升级为 computed goto (GCC/Clang &&label)
 *   - 热路径（算术、比较、分支）完全在 VM 内执行
 *   - 冷路径（invoke、field access）通过 JNI 回调到 ART
 */
#include <jni.h>
#include <android/log.h>
#include <string.h>
#include <stdlib.h>
#include "fy/page.h"

#define TAG "FY_VM"

/* VM 寄存器数量上限 */
#define VM_MAX_REGS 256

/* ============================================================
 * VM 操作码（与 buildSrc VmIsa.kt 一致）
 * 这些是逻辑值，运行时通过逆映射表转换
 * ============================================================ */
enum {
    VM_OP_NOP      = 0x00,
    VM_OP_MOVE     = 0x01,
    VM_OP_CONST_W  = 0x03,
    VM_OP_CONST_L  = 0x04,
    VM_OP_CONST_S  = 0x05,
    VM_OP_ADD      = 0x10,
    VM_OP_SUB      = 0x11,
    VM_OP_MUL      = 0x12,
    VM_OP_DIV      = 0x13,
    VM_OP_REM      = 0x14,
    VM_OP_AND      = 0x15,
    VM_OP_OR       = 0x16,
    VM_OP_XOR      = 0x17,
    VM_OP_SHL      = 0x18,
    VM_OP_SHR      = 0x19,
    VM_OP_USHR     = 0x1A,
    VM_OP_NEG      = 0x1B,
    VM_OP_NOT      = 0x1D,
    VM_OP_CMP      = 0x30,
    VM_OP_IF_EQ    = 0x40,
    VM_OP_IF_NE    = 0x41,
    VM_OP_IF_LT    = 0x42,
    VM_OP_IF_GE    = 0x43,
    VM_OP_IF_GT    = 0x44,
    VM_OP_IF_LE    = 0x45,
    VM_OP_IF_EQZ   = 0x46,
    VM_OP_IF_NEZ   = 0x47,
    VM_OP_IF_LTZ   = 0x48,
    VM_OP_IF_GEZ   = 0x49,
    VM_OP_IF_GTZ   = 0x4A,
    VM_OP_IF_LEZ   = 0x4B,
    VM_OP_GOTO     = 0x50,
    VM_OP_INVOKE   = 0x70,
    VM_OP_RETURN_V = 0xA0,
    VM_OP_RETURN   = 0xA1,
    VM_OP_JUNK     = 0xFE,
    VM_OP_HALT     = 0xFF
};

/* ============================================================
 * VM 指令结构
 * ============================================================ */
typedef struct {
    uint8_t  opcode;        /* 逻辑操作码（已通过逆映射表转换） */
    int32_t  operand_count; /* 操作数数量 */
    int32_t  operands[8];   /* 操作数（最多 8 个） */
} vm_instruction_t;

/* ============================================================
 * VM 执行上下文
 * ============================================================ */
typedef struct {
    int64_t  regs[VM_MAX_REGS];  /* 虚拟寄存器 */
    int32_t  pc;                  /* 程序计数器（指令索引） */
    int32_t  insn_count;          /* 指令总数 */
    int      running;             /* 是否在运行 */
    int      exception;           /* 是否有异常 */
    int64_t  return_value;        /* 返回值 */

    vm_instruction_t *instructions;  /* 指令数组 */
    JNIEnv *jni_env;                 /* JNI 环境（用于 invoke 回调） */
} vm_context_t;

/* ============================================================
 * 字节码解码
 *
 * 格式: count(4) + [opcode(1) + operand_count(1) + operands(N*4)] *
 * ============================================================ */
static vm_instruction_t *decode_bytecode(const uint8_t *data, size_t size,
                                         int32_t *out_count) {
    if (size < 4) return NULL;

    int32_t count;
    memcpy(&count, data, 4);

    vm_instruction_t *insns = (vm_instruction_t *)calloc(count, sizeof(vm_instruction_t));
    if (!insns) return NULL;

    const uint8_t *p = data + 4;
    const uint8_t *end = data + size;

    for (int32_t i = 0; i < count && p + 2 <= end; i++) {
        insns[i].opcode = *p++;
        insns[i].operand_count = *p++;

        for (int32_t j = 0; j < insns[i].operand_count && p + 4 <= end; j++) {
            memcpy(&insns[i].operands[j], p, 4);
            p += 4;
        }
    }

    *out_count = count;
    return insns;
}

/* ============================================================
 * 解释器核心 — switch-based dispatch
 * ============================================================ */
static int64_t vm_execute(vm_context_t *ctx) {
    ctx->running = 1;
    ctx->pc = 0;
    ctx->return_value = 0;

    while (ctx->running && ctx->pc < ctx->insn_count && !ctx->exception) {
        vm_instruction_t *insn = &ctx->instructions[ctx->pc];
        ctx->pc++;

        switch (insn->opcode) {

            /* ========= 空操作 ========= */
            case VM_OP_NOP:
                break;

                /* ========= 寄存器移动 ========= */
            case VM_OP_MOVE:
                ctx->regs[insn->operands[0]] = ctx->regs[insn->operands[1]];
                break;

                /* ========= 常量加载 ========= */
            case VM_OP_CONST_S:
                /* 8-bit 有符号常量 → 符号扩展到 64-bit */
                ctx->regs[insn->operands[0]] = (int64_t)(int8_t)insn->operands[1];
                break;

            case VM_OP_CONST_W:
                /* 32-bit 常量 → 符号扩展到 64-bit */
                ctx->regs[insn->operands[0]] = (int64_t)insn->operands[1];
                break;

            case VM_OP_CONST_L:
                /* 64-bit 常量（高 32 位 + 低 32 位） */
                ctx->regs[insn->operands[0]] =
                        (int64_t)(uint32_t)insn->operands[1] |
                                           ((int64_t)insn->operands[2] << 32);
                break;

                /* ========= 算术运算（32-bit） ========= */

            case VM_OP_ADD:
                ctx->regs[insn->operands[0]] =
                        (int32_t)ctx->regs[insn->operands[1]] +
                        (int32_t)ctx->regs[insn->operands[2]];
                break;

            case VM_OP_SUB:
                ctx->regs[insn->operands[0]] =
                        (int32_t)ctx->regs[insn->operands[1]] -
                        (int32_t)ctx->regs[insn->operands[2]];
                break;

            case VM_OP_MUL:
                ctx->regs[insn->operands[0]] =
                        (int32_t)ctx->regs[insn->operands[1]] *
                        (int32_t)ctx->regs[insn->operands[2]];
                break;

            case VM_OP_DIV: {
                int32_t divisor = (int32_t)ctx->regs[insn->operands[2]];
                if (divisor == 0) {
                    __android_log_print(ANDROID_LOG_ERROR, TAG,
                                        "division by zero at pc=%d", ctx->pc - 1);
                    ctx->exception = 1;
                    break;
                }
                ctx->regs[insn->operands[0]] =
                        (int32_t)ctx->regs[insn->operands[1]] / divisor;
                break;
            }

            case VM_OP_REM: {
                int32_t divisor = (int32_t)ctx->regs[insn->operands[2]];
                if (divisor == 0) { ctx->exception = 1; break; }
                ctx->regs[insn->operands[0]] =
                        (int32_t)ctx->regs[insn->operands[1]] % divisor;
                break;
            }

                /* ========= 位运算 ========= */

            case VM_OP_AND:
                ctx->regs[insn->operands[0]] =
                        ctx->regs[insn->operands[1]] & ctx->regs[insn->operands[2]];
                break;

            case VM_OP_OR:
                ctx->regs[insn->operands[0]] =
                        ctx->regs[insn->operands[1]] | ctx->regs[insn->operands[2]];
                break;

            case VM_OP_XOR:
                ctx->regs[insn->operands[0]] =
                        ctx->regs[insn->operands[1]] ^ ctx->regs[insn->operands[2]];
                break;

            case VM_OP_SHL:
                ctx->regs[insn->operands[0]] =
                        (int32_t)ctx->regs[insn->operands[1]] <<
                                                              ((int32_t)ctx->regs[insn->operands[2]] & 0x1F);
                break;

            case VM_OP_SHR:
                ctx->regs[insn->operands[0]] =
                        (int32_t)ctx->regs[insn->operands[1]] >>
                                                              ((int32_t)ctx->regs[insn->operands[2]] & 0x1F);
                break;

            case VM_OP_USHR:
                ctx->regs[insn->operands[0]] =
                        (uint32_t)((int32_t)ctx->regs[insn->operands[1]]) >>
                                                                          ((int32_t)ctx->regs[insn->operands[2]] & 0x1F);
                break;

            case VM_OP_NEG:
                ctx->regs[insn->operands[0]] =
                        -(int32_t)ctx->regs[insn->operands[1]];
                break;

            case VM_OP_NOT:
                ctx->regs[insn->operands[0]] =
                        ~ctx->regs[insn->operands[1]];
                break;

                /* ========= 比较 ========= */

            case VM_OP_CMP: {
                int64_t a = ctx->regs[insn->operands[1]];
                int64_t b = ctx->regs[insn->operands[2]];
                ctx->regs[insn->operands[0]] = (a > b) ? 1 : ((a < b) ? -1 : 0);
                break;
            }

                /* ========= 条件分支（两操作数比较） ========= */

            case VM_OP_IF_EQ:
                if ((int32_t)ctx->regs[insn->operands[0]] ==
                    (int32_t)ctx->regs[insn->operands[1]])
                    ctx->pc += insn->operands[2];
                break;

            case VM_OP_IF_NE:
                if ((int32_t)ctx->regs[insn->operands[0]] !=
                    (int32_t)ctx->regs[insn->operands[1]])
                    ctx->pc += insn->operands[2];
                break;

            case VM_OP_IF_LT:
                if ((int32_t)ctx->regs[insn->operands[0]] <
                    (int32_t)ctx->regs[insn->operands[1]])
                    ctx->pc += insn->operands[2];
                break;

            case VM_OP_IF_GE:
                if ((int32_t)ctx->regs[insn->operands[0]] >=
                    (int32_t)ctx->regs[insn->operands[1]])
                    ctx->pc += insn->operands[2];
                break;

            case VM_OP_IF_GT:
                if ((int32_t)ctx->regs[insn->operands[0]] >
                    (int32_t)ctx->regs[insn->operands[1]])
                    ctx->pc += insn->operands[2];
                break;

            case VM_OP_IF_LE:
                if ((int32_t)ctx->regs[insn->operands[0]] <=
                    (int32_t)ctx->regs[insn->operands[1]])
                    ctx->pc += insn->operands[2];
                break;

                /* ========= 条件分支（与零比较） ========= */

            case VM_OP_IF_EQZ:
                if ((int32_t)ctx->regs[insn->operands[0]] == 0)
                    ctx->pc += insn->operands[1];
                break;

            case VM_OP_IF_NEZ:
                if ((int32_t)ctx->regs[insn->operands[0]] != 0)
                    ctx->pc += insn->operands[1];
                break;

            case VM_OP_IF_LTZ:
                if ((int32_t)ctx->regs[insn->operands[0]] < 0)
                    ctx->pc += insn->operands[1];
                break;

            case VM_OP_IF_GEZ:
                if ((int32_t)ctx->regs[insn->operands[0]] >= 0)
                    ctx->pc += insn->operands[1];
                break;

            case VM_OP_IF_GTZ:
                if ((int32_t)ctx->regs[insn->operands[0]] > 0)
                    ctx->pc += insn->operands[1];
                break;

            case VM_OP_IF_LEZ:
                if ((int32_t)ctx->regs[insn->operands[0]] <= 0)
                    ctx->pc += insn->operands[1];
                break;

                /* ========= 无条件跳转 ========= */

            case VM_OP_GOTO:
                ctx->pc += insn->operands[0];
                break;

                /* ========= 方法调用（通过 JNI 回调到 ART） ========= */

            case VM_OP_INVOKE: {
                /*
                 * 操作数: [method_idx, reg_count, v0, v1, ...]
                 * 通过 JNI 调用 VmBridge.nativeInvoke() 来执行原始方法
                 */
                if (!ctx->jni_env) break;

                JNIEnv *env = ctx->jni_env;
                jclass bridge_cls = (*env)->FindClass(env, "com/fy/guard_stub/VmBridge");
                if (!bridge_cls) {
                    (*env)->ExceptionClear(env);
                    ctx->exception = 1;
                    break;
                }

                jmethodID invoke_mid = (*env)->GetStaticMethodID(
                        env, bridge_cls, "nativeInvoke", "(I[JI)J");
                if (!invoke_mid) {
                    (*env)->ExceptionClear(env);
                    (*env)->DeleteLocalRef(env, bridge_cls);
                    break;
                }

                jint method_idx = insn->operands[0];
                jint reg_count = insn->operands[1];
                if (reg_count > 8) reg_count = 8;

                /* 构建寄存器数组 */
                jlongArray reg_arr = (*env)->NewLongArray(env, reg_count);
                if (reg_arr) {
                    jlong reg_buf[8];
                    for (int r = 0; r < reg_count; r++)
                        reg_buf[r] = (jlong)ctx->regs[insn->operands[2 + r]];
                    (*env)->SetLongArrayRegion(env, reg_arr, 0, reg_count, reg_buf);

                    /* 调用 */
                    jlong result = (*env)->CallStaticLongMethod(
                            env, bridge_cls, invoke_mid, method_idx, reg_arr, 0);
                    ctx->return_value = result;

                    (*env)->DeleteLocalRef(env, reg_arr);
                }

                (*env)->DeleteLocalRef(env, bridge_cls);
                break;
            }

                /* ========= 返回 ========= */

            case VM_OP_RETURN_V:
                ctx->running = 0;
                break;

            case VM_OP_RETURN:
                ctx->return_value = ctx->regs[insn->operands[0]];
                ctx->running = 0;
                break;

                /* ========= 混淆指令 ========= */

            case VM_OP_JUNK:
                /* 垃圾指令，直接忽略 */
                break;

            case VM_OP_HALT:
                ctx->running = 0;
                break;

            default:
                __android_log_print(ANDROID_LOG_WARN, TAG,
                                    "unknown opcode: 0x%02x at pc=%d",
                                    insn->opcode, ctx->pc - 1);
                ctx->running = 0;
                break;
        }
    }

    if (ctx->exception) {
        __android_log_print(ANDROID_LOG_ERROR, TAG,
                            "VM exception at pc=%d", ctx->pc);
    }

    return ctx->return_value;
}

/* ============================================================
 * JNI 入口
 *
 * VmBridge.executeVm(int methodIdx, byte[] vmBytecode, long[] initRegs)
 * ============================================================ */
JNIEXPORT jlong JNICALL
Java_com_fy_guard_stub_VmBridge_executeVm(JNIEnv *env, jclass clazz,
                                          jint method_idx,
                                          jbyteArray bytecode,
                                          jlongArray init_regs) {
    /* 读取字节码 */
    jsize bc_len = (*env)->GetArrayLength(env, bytecode);
    jbyte *bc_data = (*env)->GetByteArrayElements(env, bytecode, NULL);

    /* 解码 */
    int32_t insn_count = 0;
    vm_instruction_t *insns = decode_bytecode(
    (const uint8_t *)bc_data, (size_t)bc_len, &insn_count);

    (*env)->ReleaseByteArrayElements(env, bytecode, bc_data, JNI_ABORT);

    if (!insns) {
        __android_log_print(ANDROID_LOG_ERROR, TAG,
                            "failed to decode VM bytecode for method %d",
                            method_idx);
        return 0;
    }

    /* 初始化上下文 */
    vm_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.instructions = insns;
    ctx.insn_count = insn_count;
    ctx.jni_env = env;

    /* 复制初始寄存器值 */
    if (init_regs) {
        jsize reg_count = (*env)->GetArrayLength(env, init_regs);
        if (reg_count > VM_MAX_REGS) reg_count = VM_MAX_REGS;
        (*env)->GetLongArrayRegion(env, init_regs, 0, reg_count,
                                   (jlong *)ctx.regs);
    }

    /* 执行 */
    jlong result = (jlong)vm_execute(&ctx);

    /* 清理 */
    free(insns);

    return result;
}
