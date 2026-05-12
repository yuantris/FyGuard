package com.fy.guard.buildsrc.signer

import com.fy.guard.buildsrc.SigningConfig
import org.gradle.api.Project
import java.io.File

/**
 * APK 自动签名器
 *
 * 使用 Android SDK 中的 apksigner 工具进行 v2/v3 签名。
 * 如果 apksigner 不可用，回退到 jarsigner。
 */
class AutoSigner(private val project: Project) {

    /**
     * 签名 APK
     *
     * @param apkFile  待签名的 APK
     * @param config   签名配置（keystore 路径、密码等）
     */
    fun sign(apkFile: File, config: SigningConfig) {
        project.logger.lifecycle("    keystore: ${config.storeFile}")
        project.logger.lifecycle("    key alias: ${config.keyAlias}")

        val androidSdk = findAndroidSdk()
        if (androidSdk == null) {
            project.logger.warn("    WARNING: Android SDK not found, skipping auto-sign")
            project.logger.warn("    Sign manually: apksigner sign --ks ${config.storeFile} ${apkFile.name}")
            return
        }

        val apksigner = findApksigner(androidSdk)
        if (apksigner != null) {
            signWithApksigner(apkFile, config, apksigner)
        } else {
            project.logger.warn("    WARNING: apksigner not found, signing with jarsigner")
            signWithJarsigner(apkFile, config)
        }
    }

    private fun findAndroidSdk(): String? {
        val localProperties = File(project.rootDir, "local.properties")
        if (localProperties.exists()) {
            val props = java.util.Properties()
            localProperties.inputStream().use { props.load(it) }
            val sdkDir = props.getProperty("sdk.dir")
            if (sdkDir != null) {
                val dir = File(sdkDir)
                if (dir.exists()) return sdkDir
            }
        }

        val fromProp = project.findProperty("sdk.dir")?.toString()
        if (fromProp != null) {
            val dir = File(fromProp)
            if (dir.exists()) return fromProp
        }

        val envVars = listOf("ANDROID_HOME", "ANDROID_SDK_ROOT")
        for (varName in envVars) {
            val value = System.getenv(varName)
            if (value != null) {
                val dir = File(value)
                if (dir.exists()) return value
            }
        }

        return null
    }

    private fun findApksigner(sdkDir: String): File? {
        val buildTools = File(sdkDir, "build-tools")
        if (!buildTools.exists()) return null

        val latestVersion = buildTools.listFiles()
            ?.filter { it.isDirectory }
            ?.maxByOrNull { it.name }

        if (latestVersion == null) return null

        val apksigner = File(latestVersion, "apksigner")
        val apksignerBat = File(latestVersion, "apksigner.bat")

        return when {
            apksigner.exists() -> apksigner
            apksignerBat.exists() -> apksignerBat
            else -> null
        }
    }

    private fun signWithApksigner(apk: File, config: SigningConfig, apksigner: File) {
        try {
            val signProc = ProcessBuilder(
                apksigner.absolutePath,
                "sign",
                "--ks", config.storeFile,
                "--ks-pass", "pass:${config.storePassword}",
                "--ks-key-alias", config.keyAlias,
                "--key-pass", "pass:${config.keyPassword}",
                "--out", apk.absolutePath,
                apk.absolutePath
            ).redirectErrorStream(true).start()
            signProc.inputStream.bufferedReader().readText()
            val signExit = signProc.waitFor()

            if (signExit != 0) {
                project.logger.error("    apksigner sign failed with exit code $signExit")
                return
            }
            project.logger.lifecycle("    signed with apksigner (v2/v3)")

            val verifyProc = ProcessBuilder(
                apksigner.absolutePath, "verify", "--verbose", apk.absolutePath
            ).redirectErrorStream(true).start()
            verifyProc.inputStream.bufferedReader().readText()
            verifyProc.waitFor()
        } catch (e: Exception) {
            project.logger.error("    apksigner failed: ${e.message}")
        }
    }

    private fun signWithJarsigner(apk: File, config: SigningConfig) {
        try {
            val proc = ProcessBuilder(
                "jarsigner",
                "-keystore", config.storeFile,
                "-storepass", config.storePassword,
                "-keypass", config.keyPassword,
                "-signedjar", apk.absolutePath,
                apk.absolutePath,
                config.keyAlias
            ).redirectErrorStream(true).start()
            proc.inputStream.bufferedReader().readText()
            proc.waitFor()
            project.logger.lifecycle("    signed with jarsigner (v1 only)")
        } catch (e: Exception) {
            project.logger.error("    jarsigner failed: ${e.message}")
        }
    }
}
