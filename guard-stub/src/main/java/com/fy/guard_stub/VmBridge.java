package com.fy.guard_stub;

/**
 * VmBridge — VMP 虚拟机桥接
 *
 * 连接 buildSrc VmCompiler 编译的自定义字节码和
 * native 层 vm_engine.c 的解释器。
 *
 * ============================
 * VMP 工作流程
 * ============================
 *
 * 构建时（buildSrc VmCompiler）：
 *   1. 选择关键方法（如 LicenseChecker.validate）
 *   2. 将 Dalvik 字节码翻译为自定义 VM 字节码
 *   3. 注入混淆（不透明谓词、垃圾指令、随机 opcode 映射）
 *   4. 替换原方法体为 stub（调用 VmBridge.executeVm）
 *
 * 运行时：
 *   1. 被保护的方法被调用 → stub 执行
 *   2. stub 调用 VmBridge.executeVm(methodIdx, bytecode, regs)
 *   3. JNI 层的 vm_engine.c 解码并执行 VM 字节码
 *   4. VM 遇到 invoke 指令时回调 VmBridge.nativeInvoke()
 *   5. nativeInvoke 调用原始方法（通过反射或 JNI）
 *   6. 结果返回给调用者
 *
 * ============================
 * 安全效果
 * ============================
 *
 * Frida dump 出来的 DEX 中，被 VMP 保护的方法体只包含
 * 几条调用 VmBridge 的 stub 指令，原始逻辑完全不存在。
 *
 * 静态反编译工具（jadx, jd-gui）看到的是：
 *   public int validate() {
 *       return (int) VmBridge.executeVm(1234, new byte[]{...}, null);
 *   }
 *
 * 真实逻辑隐藏在加密的 VM 字节码中，由 native 解释器执行。
 */
public class VmBridge {

    /**
     * 执行 VM 字节码
     *
     * 被保护方法的 stub 会调用此方法。
     *
     * @param methodIdx   方法索引（用于日志和查找）
     * @param vmBytecode  编译后的 VM 字节码（由 buildSrc VmCompiler 生成）
     * @param initRegs    初始寄存器值（传递方法参数），可为 null
     * @return 执行结果（long 类型，可表示 int/long/object 引用）
     */
    public static native long executeVm(int methodIdx, byte[] vmBytecode, long[] initRegs);

    /**
     * VM invoke 指令的回调
     *
     * 当 VM 解释器遇到方法调用指令时，通过此方法回调到 Java 层。
     * Java 层通过反射执行原始方法，返回结果。
     *
     * @param methodIdx 目标方法索引
     * @param args      参数数组
     * @param callType  调用类型（0=virtual, 1=super, 2=direct, 3=static, 4=interface）
     * @return 方法返回值
     *
     * 注意：此方法由 native 层通过 JNI CallStaticLongMethod 调用，
     *       但 JNI 方法签名需要匹配。当前为占位实现。
     */
    public static long nativeInvoke(int methodIdx, long[] args, int callType) {
        // TODO: 实现通过反射调用原始方法
        //
        // 完整实现需要：
        //   1. 维护 methodIdx → Method 对象的映射表
        //   2. 将 long[] args 转换为方法参数类型
        //   3. 通过 Method.invoke() 调用
        //   4. 将返回值转换为 long
        //
        // 映射表在 DEX 解密后由 native 层设置。
        android.util.Log.w("FY_VM", "nativeInvoke: method=" + methodIdx +
                " (not implemented yet)");
        return 0;
    }
}
