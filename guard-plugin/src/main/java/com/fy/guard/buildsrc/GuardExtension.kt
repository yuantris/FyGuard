package com.fy.guard.buildsrc

/**
 * guard { } DSL 配置定义
 *
 * 用户在 app/build.gradle 中这样配置：
 *
 * guard {
 *     enabled = true
 *     masterKey = "a3f1b8c92d4e6f01..."
 *
 *     dexProtection {
 *         enabled = true
 *         methodLevel = true       // 函数抽取（第二代）
 *         vmpProtection = true     // VMP 虚拟化（第三代）
 *         vmpTargetMethods = listOf(
 *             "com.example.License.check",
 *             "com.example.Crypto.decrypt"
 *         )
 *     }
 *
 *     soProtection {
 *         enabled = true
 *         multiLayer = true        // 多层壳（第四代）
 *         libraries = listOf("libnative-lib.so")
 *     }
 *
 *     resourceProtection {
 *         enabled = true
 *         patterns = listOf("*.json", "*.key", "*.dat")
 *     }
 *
 *     antiDebug = true
 *     antiFrida = true
 *     integrityCheck = true
 *
 *     signing {
 *         storeFile = "keystore.jks"
 *         storePassword = "password"
 *         keyAlias = "alias"
 *         keyPassword = "password"
 *     }
 * }
 */
import org.gradle.api.Action

open class GuardExtension {
    /** 总开关 */
    var enabled: Boolean = true

    /** AES-256 主密钥（64 位十六进制字符串） */
    var masterKey: String = ""

    /** DEX 保护配置 */
    var dexProtection: DexProtection = DexProtection()

    /** SO 保护配置 */
    var soProtection: SoProtection = SoProtection()

    /** 资源加密配置 */
    var resourceProtection: ResourceProtection = ResourceProtection()

    /** 反调试开关 */
    var antiDebug: Boolean = true

    /** 反 Frida/Xposed 开关 */
    var antiFrida: Boolean = true

    /** APK 完整性校验开关 */
    var integrityCheck: Boolean = true

    /** APK 签名配置（配置后自动签名） */
    var signing: SigningConfig? = null

    // DSL 构建器方法
    fun dexProtection(block: Action<DexProtection>) { block.execute(dexProtection) }
    fun soProtection(block: Action<SoProtection>) { block.execute(soProtection) }
    fun resourceProtection(block: Action<ResourceProtection>) { block.execute(resourceProtection) }
    fun signing(block: Action<SigningConfig>) { signing = SigningConfig().apply { block.execute(this) } }
}

/** DEX 保护选项 */
open class DexProtection {
    /** 启用 DEX 整体加密（第一代，必须开启） */
    var enabled: Boolean = true

    /** 启用函数抽取（第二代：逐方法加密，运行时按需还原） */
    var methodLevel: Boolean = false

    /** 启用 VMP 虚拟化保护（第三代：自定义字节码虚拟机） */
    var vmpProtection: Boolean = false

    /** VMP 保护的目标方法列表（格式：完整类名->方法名） */
    var vmpTargetMethods: List<String> = emptyList()
}

/** SO 保护选项 */
open class SoProtection {
    /** 启用 SO .text section 加密 */
    var enabled: Boolean = false

    /** 启用多层壳架构（Layer 1 → 2 → 3 逐层解密） */
    var multiLayer: Boolean = false

    /** 指定要保护的 SO 文件名列表，空列表 = 保护所有 SO */
    var libraries: List<String> = emptyList()
}

/** 资源加密选项 */
open class ResourceProtection {
    /** 启用资源文件加密 */
    var enabled: Boolean = false

    /** 要加密的文件扩展名模式 */
    var patterns: List<String> = listOf("*.json", "*.xml", "*.key", "*.dat")
}

/** APK 签名配置 */
open class SigningConfig {
    var storeFile: String = ""
    var storePassword: String = ""
    var keyAlias: String = ""
    var keyPassword: String = ""
}
