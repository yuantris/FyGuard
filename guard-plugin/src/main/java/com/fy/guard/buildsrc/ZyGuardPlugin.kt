package com.fy.guard.buildsrc

import com.android.build.gradle.AppPlugin
import com.fy.guard.buildsrc.manifest.ManifestProcessor
import com.fy.guard.buildsrc.task.HardenTask
import org.gradle.api.Plugin
import org.gradle.api.Project
import kotlin.jvm.java

/**
 * FY Guard 插件入口
 *
 * 用户接入方式（零侵入）：
 *   plugins {
 *       id 'com.android.application'
 *       id 'com.fy.guard'   // ← 只需要这一行
 *   }
 *   guard {
 *       masterKey = "..."   // ← 配置密钥
 *   }
 *
 * 插件在 assembleRelease 完成后自动执行加固。
 * 不需要修改任何 Java/Kotlin 代码。
 * 不需要修改 AndroidManifest.xml。
 * 不需要引入任何 native 依赖。
 */
class ZyGuardPlugin : Plugin<Project> {

    override fun apply(project: Project) {
        require(project.plugins.hasPlugin(AppPlugin::class.java)) {
            "[FY Guard] apply 'com.android.application' first"
        }

        val ext = project.extensions.create("guard", GuardExtension::class.java)

        // ============================================================
        // 阶段 1: 构建前置 Manifest 修改
        //
        // 在 AGP 的 processManifest task 之前，
        // 修改合并后的纯文本 XML Manifest。
        // 这个阶段 Manifest 还没被 aapt2 编译为 AXML。
        // ============================================================
        val manifestProcessor = ManifestProcessor(project, project.logger)
        manifestProcessor.registerManifestTransform(project)

        // ============================================================
        // 阶段 2: 构建后置加固
        //
        // assembleRelease 完成后，执行完整加固流程。
        // 如果阶段 1 成功修改了 Manifest，此处只需确认信息。
        // 如果阶段 1 失败，此处通过 aapt2 解析 AXML 来补救。
        // ============================================================
        project.afterEvaluate {
            if (!ext.enabled) {
                project.logger.lifecycle("[FY Guard] disabled")
                return@afterEvaluate
            }

            project.logger.lifecycle("")
            project.logger.lifecycle("  ╔══════════════════════════════════════╗")
            project.logger.lifecycle("  ║       FY Guard v1.0.0 Hardener       ║")
            project.logger.lifecycle("  ║  DEX+VMP+SO+AntiDebug+Resource      ║")
            project.logger.lifecycle("  ║  16K Page Compatible                 ║")
            project.logger.lifecycle("  ╚══════════════════════════════════════╝")
            project.logger.lifecycle("")

            val hardenTask = project.tasks.register(
                "hardenRelease", HardenTask::class.java
            ) { task ->
                task.extension.set(ext)
                task.group = "guard"
            }

            project.tasks.matching { it.name == "assembleRelease" }.configureEach {
                it.finalizedBy(hardenTask)
            }
        }
    }
}
