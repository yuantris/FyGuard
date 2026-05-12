//
// Created by 方方大王 on 2026/5/13.
//
/*
 * anti_frida.c — 反 Frida / Xposed / Magisk 检测
 *
 * 7 种独立检测方法，专门针对动态注入工具。
 *
 * 与 anti_debug.c 的区别：
 *   - anti_debug: 检测传统调试器（gdb/lldb）和单步调试
 *   - anti_frida: 检测运行时注入框架（Frida/Xposed/Substrate）
 *
 * Frida 的注入特征：
 *   - 通过 ptrace 注入 .so 到目标进程
 *   - 创建 frida-agent 线程
 *   - 在内存中留下 D-Bus 协议特征
 *   - 监听 TCP 27042/27043 端口
 *   - 创建 /proc/self/fd 下的命名管道
 */
#include <jni.h>
#include <android/log.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define TAG "FY_ANTIFRIDA"

/* ============================================================
 * 检测 1: /proc/self/maps 扫描
 *
 * Frida agent 注入后，其 .so 文件会出现在进程的内存映射中。
 * 扫描 maps 文件中的路径，匹配已知的注入库名。
 * ============================================================ */
static int scan_maps_for_frida(void) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;

    char line[1024];

    /* 已知注入库特征 */
    static const char *signs[] = {
            "frida-agent",          /* Frida agent (核心注入库) */
            "frida-gadget",         /* Frida gadget (嵌入式) */
            "libfrida",             /* Frida 核心库 */
            "linjector",            /* Frida 注入器 */
            "gadget.so",            /* 通用 gadget */
            "xposed",               /* Xposed 框架 */
            "libsubstrate",         /* Cydia Substrate */
            "libdexposed",          /* Dexposed */
            "libepic",              /* Epic (太极) */
            "libsandhook",          /* SandHook */
            "libwhale",             /* Whale hook 框架 */
            NULL
    };

    while (fgets(line, sizeof(line), f)) {
        for (int i = 0; signs[i]; i++) {
            if (strstr(line, signs[i])) {
                __android_log_print(ANDROID_LOG_WARN, TAG,
                                    "found '%s' in /proc/self/maps", signs[i]);
                fclose(f);
                return 1;
            }
        }
    }

    fclose(f);
    return 0;
}

/* ============================================================
 * 检测 2: 端口扫描
 *
 * Frida server 默认监听 TCP 27042 (旧版) 或 27043。
 * 如果设备上运行了 frida-server，这些端口会开放。
 * ============================================================ */
static int scan_frida_ports(void) {
    int ports[] = {27042, 27043, 0};

    for (int i = 0; ports[i]; i++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) continue;

        struct timeval tv = {0, 300000};  /* 300ms 超时 */
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(ports[i]);
        addr.sin_addr.s_addr = htonl(0x7F000001);

        int ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
        close(fd);

        if (ret == 0) {
            __android_log_print(ANDROID_LOG_WARN, TAG,
                                "Frida port %d is open", ports[i]);
            return 1;
        }
    }

    return 0;
}

/* ============================================================
 * 检测 3: /proc/self/fd 命名管道扫描
 *
 * Frida 使用 D-Bus 协议与注入的 agent 通信。
 * D-Bus 会创建 Unix domain socket 或命名管道。
 * 在 /proc/self/fd/ 的符号链接目标中可以看到 "frida" 或 "gmain"。
 * ============================================================ */
static int scan_frida_pipes(void) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/fd", getpid());

    DIR *dir = opendir(path);
    if (!dir) return 0;

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_name[0] == '.') continue;

        char link_path[512];
        char target[512];

        snprintf(link_path, sizeof(link_path), "%s/%s", path, ent->d_name);
        ssize_t len = readlink(link_path, target, sizeof(target) - 1);

        if (len > 0) {
            target[len] = '\0';
            if (strstr(target, "frida") || strstr(target, "gmain") ||
                strstr(target, "gdbus")) {
                __android_log_print(ANDROID_LOG_WARN, TAG,
                                    "suspicious fd: %s → %s", ent->d_name, target);
                closedir(dir);
                return 1;
            }
        }
    }

    closedir(dir);
    return 0;
}

/* ============================================================
 * 检测 4: 内存特征扫描
 *
 * Frida 注入后会在内存中留下特定的字节模式。
 * 扫描可读写的匿名内存映射，查找特征字符串。
 *
 * 注意：这可能较慢（需要扫描大量内存），只在初始化时执行。
 * ============================================================ */
static int scan_memory_pattern(void) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;

    char line[1024];

    while (fgets(line, sizeof(line), f)) {
        unsigned long start, end;
        char perms[5];

        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) != 3)
            continue;

        /* 只扫描可读映射 */
        if (perms[0] != 'r') continue;

        size_t region_size = end - start;

        /* 跳过过大的区域（> 10MB，避免太慢） */
        if (region_size > 10 * 1024 * 1024) continue;

        /* 在内存中搜索 "LIBFRIDA" 特征 */
        const uint8_t *mem = (const uint8_t *)start;
        for (size_t off = 0; off + 8 < region_size; off += 4096) {
            if (memcmp(mem + off, "LIBFRIDA", 8) == 0) {
                __android_log_print(ANDROID_LOG_WARN, TAG,
                                    "found 'LIBFRIDA' pattern at offset 0x%lx",
                                    start + off);
                fclose(f);
                return 1;
            }
        }
    }

    fclose(f);
    return 0;
}

/* ============================================================
 * 检测 5: Xposed 类名检测
 *
 * 通过 JNI 的 FindClass 检测 Xposed 框架的类是否已被加载。
 * 如果 FindClass 成功找到了 XposedBridge，说明 Xposed 在运行。
 * ============================================================ */
static int detect_xposed_classes(JNIEnv *env) {
    static const char *xposed_classes[] = {
            "de/robv/android/xposed/XposedBridge",
            "de/robv/android/xposed/XC_MethodHook",
            "de/robv/android/xposed/XC_MethodReplacement",
            "com/github/nicai/XposedBridge",    /* 某些修改版 */
            NULL
    };

    for (int i = 0; xposed_classes[i]; i++) {
        jclass cls = (*env)->FindClass(env, xposed_classes[i]);
        if (cls != NULL) {
            __android_log_print(ANDROID_LOG_WARN, TAG,
                                "Xposed class found: %s", xposed_classes[i]);
            (*env)->DeleteLocalRef(env, cls);
            return 1;
        }
        /* 清除 ClassNotFoundException */
        (*env)->ExceptionClear(env);
    }

    return 0;
}

/* ============================================================
 * 检测 6: 异常进程名
 *
 * 检查 /proc/self/cmdline 中是否包含调试工具的名称。
 * ============================================================ */
static int detect_abnormal_process(void) {
    FILE *f = fopen("/proc/self/cmdline", "r");
    if (!f) return 0;

    char cmd[256] = {0};
    fread(cmd, 1, sizeof(cmd) - 1, f);
    fclose(f);

    if (strstr(cmd, "frida") || strstr(cmd, "gdb") || strstr(cmd, "lldb")) {
        __android_log_print(ANDROID_LOG_WARN, TAG,
                            "abnormal cmdline: %s", cmd);
        return 1;
    }

    return 0;
}

/* ============================================================
 * 检测 7: 线程名检测
 *
 * Frida 创建的线程通常带有 "gmain"、"gdbus" 等 GLib 线程名。
 * 扫描 /proc/self/task/<tid>/comm 查找可疑线程。
* ============================================================ */
static int detect_frida_threads(void) {
    char task_path[256];
    snprintf(task_path, sizeof(task_path), "/proc/%d/task", getpid());

    DIR *dir = opendir(task_path);
    if (!dir) return 0;

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_name[0] == '.') continue;

        char comm_path[512];
        snprintf(comm_path, sizeof(comm_path), "%s/%s/comm",
                 task_path, ent->d_name);

        FILE *f = fopen(comm_path, "r");
        if (!f) continue;

        char name[64] = {0};
        fgets(name, sizeof(name), f);
        fclose(f);

        /* 去除换行符 */
        char *nl = strchr(name, '\n');
        if (nl) *nl = '\0';

        if (strstr(name, "gmain") || strstr(name, "gdbus") ||
            strstr(name, "frida") || strstr(name, "linjector")) {
            __android_log_print(ANDROID_LOG_WARN, TAG,
                                "suspicious thread: %s (tid=%s)", name, ent->d_name);
            closedir(dir);
            return 1;
        }
    }

    closedir(dir);
    return 0;
}

/* ============================================================
 * 综合检测入口
 * ============================================================ */
int fy_anti_frida_check(JNIEnv *env) {
    if (scan_maps_for_frida())   return 1;
    if (scan_frida_ports())      return 1;
    if (scan_frida_pipes())      return 1;
    if (scan_memory_pattern())   return 1;
    if (detect_abnormal_process()) return 1;
    if (detect_frida_threads())  return 1;
    if (env && detect_xposed_classes(env)) return 1;
    return 0;
}
