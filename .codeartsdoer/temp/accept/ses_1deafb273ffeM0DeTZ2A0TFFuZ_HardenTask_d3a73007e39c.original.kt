package com.fy.guard.buildsrc.task

import com.fy.guard.buildsrc.GuardExtension
import com.fy.guard.buildsrc.crypto.AesCipher
import com.fy.guard.buildsrc.dex.MethodExtractor
import com.fy.guard.buildsrc.manifest.AxmlPatcher
import com.fy.guard.buildsrc.manifest.ManifestProcessor
import com.fy.guard.buildsrc.res.ResourceEncryptor
import com.fy.guard.buildsrc.signer.AutoSigner
import com.fy.guard.buildsrc.so.SoLayerBuilder
import org.gradle.api.DefaultTask
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.TaskAction
import java.io.File
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

abstract class HardenTask : DefaultTask() {

    @get:Input
    abstract val extension: Property<GuardExtension>

    @TaskAction
    fun execute() {
        val ext = extension.get()
        val startTime = System.currentTimeMillis()

        require(ext.masterKey.length == 64 && ext.masterKey.matches(Regex("[0-9a-fA-F]+"))) {
            "[FY Guard] masterKey must be 64 hex characters"
        }

        // 定位 APK
        val apkDir = File(project.buildDir, "outputs/apk/release")
        val inputApk = apkDir.listFiles()?.find {
            it.extension == "apk" && !it.name.contains("hardened")
        } ?: error("[FY Guard] Release APK not found")

        val workDir = File(project.buildDir, "guard_tmp")
        if (workDir.exists()) workDir.deleteRecursively()
        workDir.mkdirs()

        val outputApk = File(apkDir, inputApk.name.replace(".apk", "-hardened.apk"))
        logger.lifecycle("[FY Guard] input:  ${inputApk.name}")
        logger.lifecycle("[FY Guard] output: ${outputApk.name}")

        // Step 1: 解压 APK
        logger.lifecycle("[1/8] Extracting APK...")
        val extractedDir = File(workDir, "extracted")
        extractApk(inputApk, extractedDir)

        // Step 2: 直接修改二进制 AXML StringPool，替换 Application 类名
        // 不依赖前置 hook，Gradle 增量构建可能跳过 processManifest
        logger.lifecycle("[2/8] Patching manifest (binary AXML)...")
        var realAppClass = ""

        val manifestFile = File(extractedDir, "AndroidManifest.xml")
        val axmlPatcher = AxmlPatcher(logger)
        val patchResult = axmlPatcher.patchApplicationName(
            manifestFile,
            ManifestProcessor.STUB_APPLICATION
        )

        if (patchResult.success) {
            realAppClass = patchResult.originalAppClass
            logger.lifecycle("    original app class: $realAppClass")
            logger.lifecycle("    patched to: ${ManifestProcessor.STUB_APPLICATION}")
        } else {
            logger.warn("    AxmlPatcher: ${patchResult.message}")
            logger.warn("    fallback: trying aapt2 dump...")
            val manifestProcessor = ManifestProcessor(project, logger)
            val manifestInfo = manifestProcessor.readFromApk(inputApk)
            if (manifestInfo != null) {
                realAppClass = manifestInfo.realAppClass
                logger.lifecycle("    package: ${manifestInfo.packageName}")
                logger.lifecycle("    application: ${realAppClass.ifEmpty { "(default)" }}")
            }
        }

        logger.lifecycle("[3/8] Encrypting DEX...")
        val dexKey = AesCipher.deriveKey(ext.masterKey, "DEX_GUARD")
        encryptDex(extractedDir, dexKey, ext.dexProtection)

        logger.lifecycle("[4/8] Injecting stub & native library...")
        injectStubAndNative(extractedDir)

        if (ext.soProtection.enabled) {
            logger.lifecycle("[5/8] Protecting SO...")
            val soKey = AesCipher.deriveKey(ext.masterKey, "SO_PROTECT")
            SoLayerBuilder(logger).protect(extractedDir, ext.soProtection, soKey)
        } else {
            logger.lifecycle("[5/8] SO protection: skipped")
        }

        if (ext.resourceProtection.enabled) {
            logger.lifecycle("[6/8] Encrypting resources...")
            val resKey = AesCipher.deriveKey(ext.masterKey, "RES_GUARD")
            ResourceEncryptor(logger).encrypt(extractedDir, resKey)
        } else {
            logger.lifecycle("[6/8] Resource encryption: skipped")
        }

        logger.lifecycle("[7/8] Embedding integrity data...")
        embedIntegrity(extractedDir, ext)

        logger.lifecycle("[8/8] Repackaging...")
        val unsignedApk = File(workDir, "unsigned.apk")
        repackage(extractedDir, unsignedApk)

        // zipalign: 4-byte alignment for .so and resources.arsc (Android R+ requirement)
        logger.lifecycle("[8.5/8] zipalign...")
        zipalign(unsignedApk, outputApk)

        ext.signing?.let {
            logger.lifecycle("[+] Signing APK...")
            AutoSigner(project).sign(outputApk, it)
        }

        workDir.deleteRecursively()

        val elapsed = System.currentTimeMillis() - startTime
        logger.lifecycle("")
        logger.lifecycle("╔══════════════════════════════════════════╗")
        logger.lifecycle("║  FY Guard: hardening complete!           ║")
        logger.lifecycle("║  Time: ${elapsed}ms                        ║")
        logger.lifecycle("║  Output: ${outputApk.name}      ║")
        logger.lifecycle("╚══════════════════════════════════════════╝")
    }

    private fun injectStubAndNative(dir: File) {
        File(dir, "lib/arm64-v8a").mkdirs()
        extractRes("/stub/classes.dex", File(dir, "classes.dex"))
        extractRes("/native/arm64-v8a/libfyencrypt.so",
            File(dir, "lib/arm64-v8a/libfyencrypt.so"))
    }

    private fun extractRes(path: String, target: File) {
        javaClass.getResourceAsStream(path)?.use { it.copyTo(target.outputStream()) }
            ?: error("Plugin resource not found: $path")
    }

    private fun encryptDex(dir: File, key: ByteArray,
                           cfg: com.fy.guard.buildsrc.DexProtection) {
        val dexFiles = mutableListOf<Pair<String, ByteArray>>()
        var i = 0
        while (true) {
            val n = if (i == 0) "classes.dex" else "classes${i + 1}.dex"
            val f = File(dir, n)
            if (!f.exists()) break
            dexFiles.add(n to f.readBytes())
            logger.lifecycle("    $n: ${f.length()} bytes")
            i++
        }
        if (dexFiles.isEmpty()) error("No DEX found")

        val combined = java.io.ByteArrayOutputStream()
        val dos = java.io.DataOutputStream(combined)
        dos.writeInt(dexFiles.size)
        for ((_, d) in dexFiles) { dos.writeInt(d.size); dos.write(d) }
        val plainDex = combined.toByteArray()

        var finalDex = plainDex
        var methodBlob = ByteArray(0)

        if (cfg.methodLevel) {
            val (newDex, blob) = MethodExtractor(logger).extract(plainDex, key)
            finalDex = newDex; methodBlob = blob
        }

        val enc = AesCipher.encryptWithHeader(finalDex, key, 0x44594846)
        File(dir, "assets").mkdirs()
        File(dir, "assets/enc_dex.bin").writeBytes(enc)
        if (methodBlob.isNotEmpty())
            File(dir, "assets/enc_methods.bin").writeBytes(methodBlob)

        for ((n, _) in dexFiles) File(dir, n).delete()
    }

    private fun extractApk(apk: File, dest: File) {
        ZipFile(apk).use { z ->
            z.entries().asSequence().forEach { e ->
                val f = File(dest, e.name)
                if (e.isDirectory) f.mkdirs()
                else {
                    f.parentFile.mkdirs()
                    z.getInputStream(e).copyTo(f.outputStream())
                }
            }
        }
    }

    private fun repackage(dir: File, out: File) {
        ZipOutputStream(out.outputStream().buffered()).use { z ->
            dir.walkTopDown().filter { it.isFile }.forEach { f ->
                val entryName = f.relativeTo(dir).path.replace(File.separatorChar, '/')
                val entry = ZipEntry(entryName)
                // .so and resources.arsc must use STORED (no compression)
                // to satisfy Android R+ (API 30+) requirements
                if (entryName.endsWith(".so") || entryName == "resources.arsc") {
                    entry.method = ZipEntry.STORED
                    val data = f.readBytes()
                    entry.size = data.size.toLong()
                    entry.compressedSize = data.size.toLong()
                    val crc = CRC32()
                    crc.update(data)
                    entry.crc = crc.value
                }
                z.putNextEntry(entry)
                f.inputStream().copyTo(z)
                z.closeEntry()
            }
        }
    }

    /**
     * Run zipalign to ensure 4-byte alignment for STORED entries.
     * Required for Android R+ (API 30+).
     */
    private fun zipalign(input: File, output: File) {
        val androidHome = findAndroidSdk()
            ?: error("ANDROID_HOME not set. Please set ANDROID_HOME or add sdk.dir to local.properties")
        val buildToolsDir = File(androidHome, "build-tools")
        val zipalign = buildToolsDir.listFiles()
            ?.filter { it.isDirectory }
            ?.sortedByDescending { it.name }
            ?.firstNotNullOfOrNull { File(it, "zipalign.exe") }
            ?: error("zipalign not found in $buildToolsDir")

        val proc = ProcessBuilder(zipalign.absolutePath, "-f", "4", input.absolutePath, output.absolutePath)
            .redirectErrorStream(true).start()
        val outText = proc.inputStream.bufferedReader().readText()
        val exit = proc.waitFor()
        if (exit != 0) error("zipalign failed (exit=$exit): $outText")
        logger.lifecycle("    zipalign: OK")
    }

    /**
     * 查找 Android SDK 根目录
     *
     * 优先级：
     *   1. local.properties 文件中的 sdk.dir
     *   2. project.findProperty("sdk.dir")（Gradle 属性）
     *   3. ANDROID_HOME 环境变量
     *   4. ANDROID_SDK_ROOT 环境变量
     */
    private fun findAndroidSdk(): String? {
        // 首先尝试从 local.properties 文件读取
        val localProperties = File(project.rootDir, "local.properties")
        if (localProperties.exists()) {
            val props = java.util.Properties()
            localProperties.inputStream().use { props.load(it) }
            val sdkDir = props.getProperty("sdk.dir")
            if (sdkDir != null) {
                val dir = File(sdkDir)
                if (dir.exists()) {
                    logger.lifecycle("    [SDK] found sdk.dir in local.properties: $sdkDir")
                    return sdkDir
                }
            }
        }

        // 尝试从 Gradle properties 读取
        val fromProp = project.findProperty("sdk.dir")?.toString()
        if (fromProp != null) {
            val dir = File(fromProp)
            if (dir.exists()) return fromProp
        }

        // 从环境变量读取
        val envVars = listOf("ANDROID_HOME", "ANDROID_SDK_ROOT")
        for (varName in envVars) {
            val value = System.getenv(varName)
            if (value != null) {
                val dir = File(value)
                if (dir.exists()) return value
            }
        }

        logger.warn("    [SDK] Android SDK not found")
        return null
    }

    private fun embedIntegrity(dir: File, ext: GuardExtension) {
        File(dir, "assets").mkdirs()
        val certHash = try {
            val metaDir = File(dir, "META-INF")
            val cert = metaDir.listFiles()?.find {
                it.name.uppercase().endsWith(".RSA") ||
                        it.name.uppercase().endsWith(".DSA") ||
                        it.name.uppercase().endsWith(".EC")
            }
            cert?.let { AesCipher.sha256(it.readBytes()) } ?: ByteArray(32)
        } catch (_: Exception) { ByteArray(32) }

        val flags = (if (ext.antiDebug) 1 else 0) or
                (if (ext.antiFrida) 2 else 0) or
                (if (ext.integrityCheck) 4 else 0)
        val blob = java.nio.ByteBuffer.allocate(40)
            .order(java.nio.ByteOrder.LITTLE_ENDIAN)
            .putInt(1).putInt(flags).put(certHash).array()
        File(dir, "assets/integrity.dat").writeBytes(blob)
    }
}
