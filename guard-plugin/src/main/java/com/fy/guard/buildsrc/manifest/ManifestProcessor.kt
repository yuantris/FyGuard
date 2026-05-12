package com.fy.guard.buildsrc.manifest

import org.gradle.api.Project
import org.gradle.api.logging.Logger
import java.io.File
import java.nio.charset.Charset
import javax.xml.parsers.DocumentBuilderFactory
import javax.xml.transform.TransformerFactory
import javax.xml.transform.dom.DOMSource
import javax.xml.transform.stream.StreamResult

/**
 * AndroidManifest.xml 处理器
 *
 * ============================
 * 核心问题：APK 中的 Manifest 是二进制 AXML 格式
 * ============================
 *
 * APK 里的 AndroidManifest.xml 不是纯文本 XML，
 * 而是 Android 专有的二进制 AXML (Android Binary XML)。
 *
 * AXML 结构：
 *   - Header (magic + fileSize)
 *   - String Pool (所有字符串的紧凑编码)
 *   - Resource ID Table (属性名 → android.R.attr 映射)
 *   - XML Tree (节点层级，属性用 stringPool 索引引用)
 *
 * Java 标准 XML 解析器（DocumentBuilderFactory 等）无法读取 AXML。
 * 直接 parse 会抛 "Content is not allowed in prolog" 异常。
 *
 * ============================
 * 两种处理模式
 * ============================
 *
 * 模式 A: 前置修改（推荐）
 *   Hook AGP 的 processManifest task，在 aapt2 编译 Manifest 之前
 *   拦截合并后的纯文本 XML，直接用 DOM 解析修改。
 *   此时 Manifest 还没被编译为 AXML，不存在格式问题。
 *
 * 模式 B: 后置解析（备用）
 *   用 Android SDK 的 aapt2 工具将二进制 AXML dump 为可读文本，
 *   解析 dump 输出提取 Application 类名等信息。
 *   修改后用 aapt2 link 重新编译为 AXML。
 */
class ManifestProcessor(
    private val project: Project,
    private val logger: Logger
) {
    companion object {
        const val STUB_APPLICATION = "com.fy.guard_stub.StubApplication"
        const val META_REAL_APP = "com.fy.guard_stub.real_app_class"
        const val NS_ANDROID = "http://schemas.android.com/apk/res/android"
    }

    data class ManifestInfo(
        val realAppClass: String,
        val packageName: String,
        val hasCustomApplication: Boolean
    )

    // ================================================================
    // 模式 A: 前置修改（在 processManifest task 之前拦截纯文本 XML）
    // ================================================================

    /**
     * 注册 Manifest 前置修改 Hook
     *
     * 在 AGP 的构建流水线中，Manifest 经过以下阶段：
     *   1. merge  — 合并所有 source set 的 Manifest（纯文本 XML）
     *   2. process — aapt2 编译为 AXML 二进制
     *   3. package — 放入 APK
     *
     * 我们在第 2 步的 task 执行前（doFirst）拦截，
     * 此时 Manifest 仍然是纯文本 XML，可以正常用 DOM 解析。
     */
    fun registerManifestTransform(project: Project) {
        project.afterEvaluate {
            // AGP 8.x 的 Manifest 处理 task 名称
            val taskNames = listOf(
                "processReleaseMainManifest",
                "processReleaseManifest",
                "processDebugMainManifest",
                "processDebugManifest"
            )

            var hooked = false
            for (name in taskNames) {
                val task = project.tasks.findByName(name) ?: continue

                task.doLast {
                    logger.lifecycle("[FY Guard] intercepting manifest before AXML compilation...")

                    val mergedManifest = findMergedManifest(project.buildDir)
                    if (mergedManifest != null && mergedManifest.exists()) {
                        try {
                            modifyPlainXmlManifest(mergedManifest)
                            hooked = true
                        } catch (e: Exception) {
                            logger.warn("[FY Guard] plain XML modification failed: ${e.message}")
                            logger.warn("[FY Guard] will fall back to aapt2 post-processing")
                        }
                    }
                }

                logger.lifecycle("[FY Guard] hooked manifest task: $name")
                hooked = true
                break
            }

            if (!hooked) {
                logger.lifecycle("[FY Guard] no manifest task found, " +
                        "will use aapt2 post-processing")
            }
        }
    }

    /**
     * 查找 AGP 合并后的 Manifest（纯文本 XML 阶段）
     *
     * AGP 合并后的 Manifest 位于 intermediates 目录中，
     * 路径因 AGP 版本和 build variant 而异。
     *
     * 识别方法：纯文本 XML 以 "<" 或 "<?xml" 开头，
     * 而 AXML 以 0x00080003（little-endian）开头。
     */
    private fun findMergedManifest(buildDir: File): File? {
        // 先尝试已知路径
        val candidates = listOf(
            "intermediates/merged_manifest/release/AndroidManifest.xml",
            "intermediates/merged_manifests/release/AndroidManifest.xml",
            "intermediates/merged_manifests/releaseProcessReleaseManifest/AndroidManifest.xml",
            "intermediates/merged_manifest/debug/AndroidManifest.xml",
            "intermediates/merged_manifests/debug/AndroidManifest.xml"
        )

        for (path in candidates) {
            val file = File(buildDir, path)
            if (file.exists() && isPlainTextXml(file)) return file
        }

        // 递归搜索兜底
        val searchDir = File(buildDir, "intermediates")
        if (searchDir.exists()) {
            searchDir.walkTopDown()
                .filter { it.name == "AndroidManifest.xml" }
                .forEach { file ->
                    if (isPlainTextXml(file)) return file
                }
        }

        return null
    }

    /**
     * 判断文件是纯文本 XML 还是二进制 AXML
     *
     * AXML 文件的前 4 字节是 magic number:
     *   0x00080003（LE）→ 0x03 0x00 0x08 0x00
     *
     * 纯文本 XML 的前几个字节:
     *   "<?xm" (带 BOM 或 XML 声明)
     *   "<man" (直接以 <manifest> 开始)
     *   "<!--" (以注释开始)
     */
    private fun isPlainTextXml(file: File): Boolean {
        return try {
            val header = file.readBytes().take(4).toByteArray()
            if (header.size < 4) return false

            // 排除 AXML magic: 0x03 0x00 0x08 0x00
            val isAxml = header[0] == 0x03.toByte() &&
                    header[1] == 0x00.toByte() &&
                    header[2] == 0x08.toByte() &&
                    header[3] == 0x00.toByte()
            !isAxml
        } catch (_: Exception) {
            false
        }
    }

    /**
     * 修改纯文本 XML 格式的 Manifest（模式 A 的核心逻辑）
     *
     * 此方法在 AGP processManifest 之前被调用，
     * 输入是合并后的纯文本 XML，可以正常用 DOM 解析。
     *
     * 修改内容：
     *   1. 将 android:name 替换为 StubApplication
     *   2. 插入 meta-data 保存原始 Application 类名
     *   3. 设置 android:extractNativeLibs="true"
     */
    fun modifyPlainXmlManifest(manifestFile: File): ManifestInfo {
        logger.lifecycle("    [Manifest] processing plain-text XML: ${manifestFile.path}")

        val dbf = DocumentBuilderFactory.newInstance().apply {
            isNamespaceAware = true
            // 禁用外部实体解析（安全）
            setFeature("http://xml.org/sax/features/external-general-entities", false)
            setFeature("http://xml.org/sax/features/external-parameter-entities", false)
        }

        val doc = dbf.newDocumentBuilder().parse(manifestFile)
        val root = doc.documentElement

        val packageName = root.getAttribute("package")
        logger.lifecycle("    [Manifest] package: $packageName")

        // 查找 <application> 节点
        val appNodes = root.getElementsByTagName("application")
        if (appNodes.length == 0) {
            logger.warn("    [Manifest] no <application> tag found")
            return ManifestInfo("", packageName, false)
        }
        val appNode = appNodes.item(0)

        // 读取原始 android:name
        val realAppClass = appNode.attributes
            .getNamedItemNS(NS_ANDROID, "name")?.nodeValue ?: ""
        logger.lifecycle("    [Manifest] original application: " +
                realAppClass.ifEmpty { "(default)" })

        // 替换 android:name 为 StubApplication
        val nameAttr = doc.createAttributeNS(NS_ANDROID, "android:name")
        nameAttr.nodeValue = STUB_APPLICATION
        appNode.attributes.setNamedItemNS(nameAttr)

        // 插入 meta-data 保存真实类名
        if (realAppClass.isNotEmpty()) {
            val meta = doc.createElement("meta-data")
            meta.setAttributeNS(NS_ANDROID, "android:name", META_REAL_APP)
            meta.setAttributeNS(NS_ANDROID, "android:value", realAppClass)
            appNode.appendChild(meta)
            logger.lifecycle("    [Manifest] saved real class to meta-data")
        }

        // 设置 extractNativeLibs="true"（native 库需要被解压才能加载）
        val extractAttr = doc.createAttributeNS(NS_ANDROID, "android:extractNativeLibs")
        extractAttr.nodeValue = "true"
        appNode.attributes.setNamedItemNS(extractAttr)

        // 写回文件
        val transformer = TransformerFactory.newInstance().newTransformer()
        transformer.transform(DOMSource(doc), StreamResult(manifestFile))

        logger.lifecycle("    [Manifest] rewritten: " +
                "$realAppClass → $STUB_APPLICATION")

        return ManifestInfo(realAppClass, packageName, realAppClass.isNotEmpty())
    }

    // ================================================================
    // 模式 B: aapt2 解码（处理 APK 中的 AXML 二进制 Manifest）
    // ================================================================

    /**
     * 从已打包的 APK 中读取 Manifest 信息
     *
     * 使用 aapt2 dump xmltree 命令解析二进制 AXML。
     *
     * aapt2 dump xmltree 输出示例：
     *   N: android=http://schemas.android.com/apk/res/android
     *     E: manifest (line=2)
     *       A: package="com.example.myapp" (Raw: "com.example.myapp")
     *       E: application (line=7)
     *         A: android:name(0x01010003)="com.example.MyApp"
     *         E: meta-data (line=9)
     *           A: android:name(0x01010003)="com.fy.guard_stub.real_app_class"
     *           A: android:value(0x01010003)="com.example.MyApp"
     *
     * @param apkFile APK 文件
     * @return ManifestInfo，aapt2 不可用时返回 null
     */
    fun readFromApk(apkFile: File): ManifestInfo? {
        val aapt2 = findAapt2()
        if (aapt2 == null) {
            logger.error("    [Manifest] aapt2 not found!")
            logger.error("    [Manifest] Set ANDROID_HOME or install build-tools")
            return null
        }

        logger.lifecycle("    [Manifest] parsing AXML with aapt2: ${aapt2.absolutePath}")

        // 使用 ProcessBuilder 调用 aapt2（不依赖 Gradle 的 exec API）
        val dump = runProcess(
            aapt2.absolutePath,
            "dump", "xmltree",
            "--file", "AndroidManifest.xml",
            apkFile.absolutePath
        )

        if (dump == null) {
            logger.error("    [Manifest] aapt2 dump failed")
            return null
        }

        logger.lifecycle("    [Manifest] aapt2 dump: ${dump.length} chars")
        return parseAapt2Dump(dump)
    }

    /**
     * 解析 aapt2 dump xmltree 的输出
     *
     * 输出格式分析：
     *   - "N:" 命名空间声明
     *   - "E: elementName (line=N)" 元素节点
     *   - "A: attrName(0xresourceId)=value" 属性节点
     *   - 缩进（2 空格/级）表示层级
     *
     * 我们关心的属性：
     *   - <manifest package="...">             → 包名
     *   - <application android:name="...">     → Application 类名
     *   - <meta-data android:name="com.fy.guard_stub.real_app_class"
     *               android:value="...">      → 已加固 APK 的真实类名
     */
    private fun parseAapt2Dump(dump: String): ManifestInfo {
        var packageName = ""
        var appClassName = ""
        var inApplication = false
        var inMetaDataForRealApp = false
        var applicationIndent = 0

        for (line in dump.lines()) {
            val trimmed = line.trimStart()
            val indent = line.length - trimmed.length

            // 解析 <manifest package="...">
            // 格式: A: package="com.example.myapp" (Raw: "com.example.myapp")
            if (trimmed.startsWith("A: package=")) {
                packageName = extractQuotedValue(trimmed) ?: ""
            }

            // 检测 <application> 元素
            // 格式: E: application (line=7)
            if (trimmed.startsWith("E: application")) {
                inApplication = true
                applicationIndent = indent
            }

            // 离开 <application>（缩进回退到 application 同级或更少）
            if (inApplication && indent <= applicationIndent &&
                !trimmed.startsWith("E: application") &&
                trimmed.startsWith("E: ")) {
                inApplication = false
                inMetaDataForRealApp = false
            }

            if (!inApplication) continue

            // 解析 android:name 属性
            // 格式: A: android:name(0x01010003)="com.example.MyApp"
            // 或:   A: http://schemas.android.com/apk/res/android:name(0x01010003)="com.example.MyApp"
            if (trimmed.startsWith("A: android:name") || trimmed.startsWith("A: http://schemas.android.com/apk/res/android:name")) {
                val value = extractQuotedValue(trimmed)

                // 检查是否是 meta-data 的 android:name = "com.fy.guard_stub.real_app_class"
                if (value == META_REAL_APP) {
                    inMetaDataForRealApp = true
                } else if (value != null && value != STUB_APPLICATION &&
                    appClassName.isEmpty()) {
                    // <application android:name="..."> 的值
                    appClassName = value
                }
            }

            // 如果当前 meta-data 是 real_app_class，读取其 value
            // 格式: A: android:value(0x01010003)="some_value"
            // 或:   A: http://schemas.android.com/apk/res/android:value(0x01010003)="some_value"
            if (inMetaDataForRealApp && (trimmed.startsWith("A: android:value") || trimmed.startsWith("A: http://schemas.android.com/apk/res/android:value"))) {
                val value = extractQuotedValue(trimmed)
                if (value != null) {
                    appClassName = value
                    logger.lifecycle("    [Manifest] found real app class in meta-data: $value")
                }
                inMetaDataForRealApp = false
            }
        }

        val hasCustom = appClassName.isNotEmpty() && appClassName != STUB_APPLICATION

        logger.lifecycle("    [Manifest] package: $packageName")
        logger.lifecycle("    [Manifest] application: ${appClassName.ifEmpty { "(default)" }}")
        logger.lifecycle("    [Manifest] already hardened: " +
                "${appClassName == STUB_APPLICATION}")

        return ManifestInfo(
            realAppClass = appClassName,
            packageName = packageName,
            hasCustomApplication = hasCustom
        )
    }

    /**
     * 从 aapt2 dump 行中提取引号内的值
     *
     * 匹配格式:
     *   A: package="com.example.myapp" (Raw: "com.example.myapp")
     *   A: android:name(0x01010003)="com.example.MyApp" (Raw: "...")
     *   A: android:value(0x01010003)="some_value" (Raw: "some_value")
     *
     * 提取第一个 "=" 之后、引号对之间的内容。
     */
    private fun extractQuotedValue(line: String): String? {
        val eqIdx = line.indexOf('=')
        if (eqIdx < 0) return null

        val afterEq = line.substring(eqIdx + 1).trimStart()
        if (!afterEq.startsWith("\"")) return null

        val endQuote = afterEq.indexOf('"', 1)
        if (endQuote < 0) return null

        return afterEq.substring(1, endQuote)
    }

    /**
     * 使用 aapt2 重新生成 AXML Manifest 并替换 APK 中的
     *
     * 流程：
     *   1. 根据 ManifestInfo 生成纯文本 XML
     *   2. aapt2 compile → .flat 中间格式
     *   3. aapt2 link → AXML 二进制
     *   4. 替换原始 Manifest
     *
     * 注意：这个方法比较复杂，实际项目中更常用的做法是
     * 通过模式 A 在编译前直接修改纯文本 XML。
     * 模式 B 作为 aapt2 不可用时的降级方案。
     *
     * @param apkDir     APK 解压目录
     * @param info       从 aapt2 dump 解析出的原始 Manifest 信息
     * @param realClass  真实 Application 类名
     */
    fun rewriteAxmlManifest(apkDir: File, info: ManifestInfo, realClass: String) {
        logger.lifecycle("    [Manifest] rewriting AXML manifest...")

        val aapt2 = findAapt2()
        val androidJar = findAndroidJar()

        if (aapt2 == null || androidJar == null) {
            logger.error("    [Manifest] aapt2 or android.jar not found")
            logger.error("    [Manifest] cannot rebuild AXML, skipping Manifest rewrite")
            return
        }

        val manifestFile = File(apkDir, "AndroidManifest.xml")
        val tempXml = File(apkDir, "AndroidManifest_new.xml")
        val tempOutput = File(apkDir, "AndroidManifest_axml.apk")

        try {
            // 1. 生成纯文本 XML
            val xmlContent = buildPlainXml(info.packageName, realClass)
            tempXml.writeText(xmlContent, Charset.forName("UTF-8"))
            logger.lifecycle("    [Manifest] generated plain XML: ${tempXml.length()} bytes")
            logger.lifecycle("    [Manifest] XML content preview: ${xmlContent.take(200).replace("\n", "\\n")}")

            // 验证文件是否正确写入
            val readBack = tempXml.readText(Charset.forName("UTF-8"))
            logger.lifecycle("    [Manifest] file read-back length: ${readBack.length} bytes")
            if (readBack != xmlContent) {
                logger.error("    [Manifest] WARNING: file content mismatch!")
            }

            // 2. 使用 aapt2 link 生成完整 APK
            logger.lifecycle("    [Manifest] running: aapt2 link -I ${androidJar.absolutePath} --manifest ${tempXml.absolutePath} -o ${tempOutput.absolutePath}")
            val linkExit = runProcessRaw(
                aapt2.absolutePath,
                "link",
                "-I", androidJar.absolutePath,
                "--manifest", tempXml.absolutePath,
                "-o", tempOutput.absolutePath,
                "--auto-add-overlay"
            )
            if (linkExit != 0) {
                logger.error("    [Manifest] aapt2 link failed (exit=$linkExit)")
                return
            }

            // 3. 从生成的 APK 中提取 AndroidManifest.xml
            extractManifestFromApk(tempOutput, manifestFile)

            logger.lifecycle("    [Manifest] AXML manifest rewritten successfully")

        } finally {
            // 清理临时文件
            tempXml.delete()
            tempOutput.delete()
        }
    }

    /**
     * 从 aapt2 link 生成的 APK 中提取 AndroidManifest.xml
     */
    private fun extractManifestFromApk(apkFile: File, destFile: File) {
        try {
            java.util.zip.ZipFile(apkFile).use { zip ->
                val entry = zip.getEntry("AndroidManifest.xml")
                if (entry != null) {
                    destFile.delete()
                    zip.getInputStream(entry).use { input ->
                        destFile.outputStream().use { output ->
                            input.copyTo(output)
                        }
                    }
                    logger.lifecycle("    [Manifest] extracted AXML from aapt2 output: " +
                            "${destFile.length()} bytes")
                } else {
                    logger.error("    [Manifest] AndroidManifest.xml not found in aapt2 output")
                }
            }
        } catch (e: Exception) {
            logger.error("    [Manifest] failed to extract from aapt2 output: ${e.message}")
        }
    }

    /**
     * 生成纯文本 XML Manifest
     */
    private fun buildPlainXml(packageName: String, realClass: String): String {
        return """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="$packageName">

    <application
        android:name="$STUB_APPLICATION"
        android:extractNativeLibs="true">
        <meta-data
            android:name="$META_REAL_APP"
            android:value="$realClass" />
    </application>

</manifest>"""
    }

    // ================================================================
    // 进程执行工具（使用标准 Java ProcessBuilder，不依赖 Gradle API）
    // ================================================================

    /**
     * 执行外部进程并捕获 stdout
     *
     * 使用标准 Java ProcessBuilder，不依赖 Gradle 的 Project.exec()。
     * 这避免了 "Unresolved reference 'exec'" 的编译错误。
     *
     * @return stdout 输出，进程失败返回 null
     */
    private fun runProcess(vararg command: String): String? {
        return try {
            val pb = ProcessBuilder(*command)
            pb.redirectErrorStream(false)

            val process = pb.start()

            val stdout = process.inputStream.bufferedReader().readText()
            val stderr = process.errorStream.bufferedReader().readText()
            val exitCode = process.waitFor()

            if (exitCode != 0) {
                logger.error("    [Process] command failed (exit=$exitCode): ${command.joinToString(" ")}")
                if (stderr.isNotBlank()) {
                    logger.error("    [Process] stderr: $stderr")
                }
                null
            } else {
                stdout
            }
        } catch (e: Exception) {
            logger.error("    [Process] execution error: ${e.message}")
            null
        }
    }

    /**
     * 执行外部进程（只关心 exit code，不捕获输出）
     */
    private fun runProcessRaw(vararg command: String): Int {
        return try {
            logger.lifecycle("    [Process] executing: ${command.joinToString(" ")}")
            val pb = ProcessBuilder(*command)

            val process = pb.start()

            val stdout = process.inputStream.bufferedReader().readText()
            val stderr = process.errorStream.bufferedReader().readText()
            val exitCode = process.waitFor()

            if (exitCode != 0) {
                logger.warn("    [Process] exit code: $exitCode")
                if (stdout.isNotBlank()) {
                    logger.warn("    [Process] stdout: ${stdout.take(500)}")
                }
                if (stderr.isNotBlank()) {
                    logger.warn("    [Process] stderr: ${stderr.take(500)}")
                }
            } else if (stdout.isNotBlank()) {
                logger.lifecycle("    [Process] stdout: ${stdout.take(200)}")
            }

            exitCode
        } catch (e: Exception) {
            logger.error("    [Process] execution error: ${e.message}")
            -1
        }
    }

    // ================================================================
    // Android SDK 工具查找
    // ================================================================

    /**
     * 查找 aapt2 可执行文件
     *
     * 搜索路径：
     *   $ANDROID_HOME/build-tools/<version>/aapt2
     *   $ANDROID_SDK_ROOT/build-tools/<version>/aapt2
     *   local.properties 中的 sdk.dir
     */
    private fun findAapt2(): File? {
        val sdkDir = findAndroidSdk() ?: run {
            logger.warn("    [SDK] Android SDK not found (set ANDROID_HOME)")
            return null
        }

        val buildTools = File(sdkDir, "build-tools")
        if (!buildTools.exists()) {
            logger.warn("    [SDK] build-tools not found: ${buildTools.path}")
            return null
        }

        // 按版本号排序，取最新
        val versions = buildTools.listFiles()
            ?.filter { it.isDirectory }
            ?.sortedByDescending {
                // 版本号格式: "34.0.0" → 排序用
                it.name.split(".").mapNotNull { s -> s.toIntOrNull() }
                    .fold(0) { acc, n -> acc * 1000 + n }
            }
            ?: return null

        for (versionDir in versions) {
            val aapt2 = File(versionDir, "aapt2")
            val aapt2Exe = File(versionDir, "aapt2.exe")

            val found = when {
                aapt2.exists() && aapt2.canExecute() -> aapt2
                aapt2Exe.exists() -> aapt2Exe
                else -> null
            }

            if (found != null) {
                logger.lifecycle("    [SDK] aapt2: ${found.path}")
                return found
            }
        }

        logger.warn("    [SDK] aapt2 not found in any build-tools version")
        return null
    }

    /**
     * 查找 android.jar（aapt2 link 需要）
     */
    private fun findAndroidJar(): File? {
        val sdkDir = findAndroidSdk() ?: return null
        val platforms = File(sdkDir, "platforms")
        if (!platforms.exists()) return null

        val latest = platforms.listFiles()
            ?.filter { it.isDirectory && it.name.startsWith("android-") }
            ?.maxByOrNull {
                it.name.removePrefix("android-").toIntOrNull() ?: 0
            }
            ?: return null

        val jar = File(latest, "android.jar")
        return if (jar.exists()) {
            logger.lifecycle("    [SDK] android.jar: ${jar.path}")
            jar
        } else {
            logger.warn("    [SDK] android.jar not found in ${latest.path}")
            null
        }
    }

    /**
     * 查找 Android SDK 根目录
     *
     * 优先级：
     *   1. local.properties 文件中的 sdk.dir（直接读取文件）
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

        return null
    }
}
