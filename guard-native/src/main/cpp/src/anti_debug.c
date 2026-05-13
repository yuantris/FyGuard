//
// Created by 方方大王 on 2026/5/13.
//
/*
 * anti_debug.c — 反调试矩阵
 *
 * 6 种独立检测方法，任意一种命中即判定为被调试环境。
 * 后台监控线程每 3 秒执行一次综合检测。
 *
 * 检测方法总览：
 *   1. ptrace 自附加     — 一个进程只能被 ptrace 一次
 *   2. /proc/self/status  — 读取 TracerPid 字段
 *   3. /proc/self/maps    — 扫描调试工具注入的库
 *   4. 时序检测           — 单步调试导致执行时间异常
 *   5. 信号陷阱           — SIGTRAP 是否被调试器拦截
 *   6. 端口扫描           — JDWP/Frida 默认端口
 */
#include <jni.h>
#include <android/log.h>
#include <pthread.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "fy/page.h"

#define TAG "FY_ANTIDBG"

/* ============================================================
 * 检测方法 1: ptrace 自附加
 *
 * 原理：
 *   一个进程在同一时刻只能被一个 tracer ptrace。
 *   如果调试器（如 gdb/lldb）已经 attach 到我们的进程，
 *   那么我们尝试 ptrace(PTRACE_ATTACH, 自己的 PID) 会失败。
 *
 * 实现：
 *   fork 子进程 → 子进程尝试 attach 父进程
 *   → 成功: 父进程没被调试 → 子进程 detach 并退出(0)
 *   → 失败: 父进程正在被调试 → 子进程退出(1)
 *
 * 副作用：
 *   成功 attach 后会暂停父进程，需要立即 detach + waitpid 唤醒
 * ============================================================ */
static int detect_ptrace(void) {
    pid_t child = fork();

    if (child == 0) {
        /* 子进程 */
        pid_t parent = getppid();

        if (ptrace(PTRACE_ATTACH, parent, NULL, NULL) == 0) {
            /* attach 成功 → 父进程没有被调试 */
            waitpid(parent, NULL, 0);                    /* 等待父进程暂停 */
            ptrace(PTRACE_DETACH, parent, NULL, NULL);   /* 立即 detach */
            _exit(0);  /* 表示：安全 */
        } else {
            /* attach 失败 → 父进程正在被调试器 attach */
            _exit(1);  /* 表示：被调试 */
        }
    }

    if (child > 0) {
        /* 父进程 */
        int status;
        waitpid(child, &status, 0);
        if (WIFEXITED(status) && WEXITSTATUS(status) == 1) {
            __android_log_print(ANDROID_LOG_WARN, TAG, "ptrace: debugger detected");
            return 1;
        }
    }

    return 0;
}

/* ============================================================
 * 检测方法 2: /proc/self/status TracerPid
 *
 * Linux 内核在 /proc/[pid]/status 中记录 TracerPid 字段。
 * 如果进程正在被调试，TracerPid 为调试器的 PID。
 * 如果没有被调试，TracerPid 为 0。
 * ============================================================ */
static int detect_tracer_pid(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int pid = atoi(line + 10);
            fclose(f);
            if (pid != 0) {
                __android_log_print(ANDROID_LOG_WARN, TAG,
                                    "TracerPid: %d (debugger attached)", pid);
                return 1;
            }
            return 0;
        }
    }

    fclose(f);
    return 0;
}

/* ============================================================
 * 检测方法 3: /proc/self/maps 扫描调试库
 *
 * 检查进程的内存映射中是否包含已知调试工具的库文件。
 * Frida 注入时会在 maps 中出现 "frida-agent" 等字样。
 * ============================================================ */
static int detect_debug_libs(void) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;

    char line[512];

    /* 已知调试/注入工具的特征字符串 */
    static const char *patterns[] = {
            "frida-agent",      /* Frida agent */
            "frida-gadget",     /* Frida gadget */
            "libfrida",         /* Frida 核心库 */
            "linjector",        /* Frida injector */
            "xposed",           /* Xposed 框架 */
            "libsubstrate",     /* Cydia Substrate */
            "libdexposed",      /* Dexposed */
            "libepic",          /* Epic (太极) */
            "libsandhook",      /* SandHook */
            "libnative-bridge", /* Native Bridge (模拟器) */
            NULL
    };

    while (fgets(line, sizeof(line), f)) {
        for (int i = 0; patterns[i]; i++) {
            if (strstr(line, patterns[i])) {
                __android_log_print(ANDROID_LOG_WARN, TAG,
                                    "suspicious lib in maps: %s", patterns[i]);
                fclose(f);
                return 1;
            }
        }
    }

    fclose(f);
    return 0;
}

/* ============================================================
 * 检测方法 4: 时序检测
 *
 * 原理：
 *   单步调试器（如 gdb step）会暂停程序执行每条指令。
 *   这会导致原本微秒级的代码块执行时间膨胀到毫秒甚至秒级。
 *
 * 方法：
 *   执行一段计算密集的代码，测量耗时。
 *   如果超过阈值（10ms），判定为被调试。
 *
 * 注意：
 *   在低端设备或 CPU 负载高时可能误报。
 *   阈值设置需要平衡灵敏度和误报率。
 * ============================================================ */
static int detect_timing(void) {
    struct timespec t1, t2;
    clock_gettime(CLOCK_MONOTONIC, &t1);

    /* 执行一段固定计算（xorshift 伪随机，约 1000 次迭代） */
    volatile uint32_t x = 0x12345678;
    for (int i = 0; i < 1000; i++) {
        x ^= (x << 13);
        x ^= (x >> 17);
        x ^= (x << 5);
    }
    (void)x;

    clock_gettime(CLOCK_MONOTONIC, &t2);

    long ns = (t2.tv_sec - t1.tv_sec) * 1000000000L +
              (t2.tv_nsec - t1.tv_nsec);

    /* 阈值: 10ms（正常情况 < 100μs，被调试时可能 > 10ms） */
    if (ns > 10000000L) {
        __android_log_print(ANDROID_LOG_WARN, TAG,
                            "timing anomaly: %ld ns (threshold: 10000000)", ns);
        return 1;
    }

    return 0;
}

/* ============================================================
 * 检测方法 5: SIGTRAP 信号陷阱
 *
 * 原理：
 *   调试器通常会拦截 SIGTRAP 信号（断点指令触发的信号）。
 *   如果我们 raise(SIGTRAP) 后自己的 handler 没有被调用，
 *   说明信号被调试器吞掉了。
 * ============================================================ */
static volatile int g_signal_caught = 0;

static void sigtrap_handler(int sig) {
    (void)sig;
    g_signal_caught = 1;
}

static int detect_signal_debug(void) {
    /* 安装 SIGTRAP handler */
    struct sigaction sa, old_sa;
    sa.sa_handler = sigtrap_handler;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTRAP, &sa, &old_sa);

    g_signal_caught = 0;

    /* 给自己发 SIGTRAP */
    raise(SIGTRAP);

    /* 恢复原始 handler */
    sigaction(SIGTRAP, &old_sa, NULL);

    /* 如果 handler 没被调用，说明调试器拦截了信号 */
    if (g_signal_caught == 0) {
        __android_log_print(ANDROID_LOG_WARN, TAG,
                            "SIGTRAP intercepted (debugger present)");
        return 1;
    }

    return 0;
}

/* ============================================================
 * 检测方法 6: 端口扫描
 *
 * 扫描已知调试工具的默认端口：
 *   - Frida server 默认监听 TCP 27042 / 27043
 *   - JDWP 默认监听 TCP 8000-8100
 *
 * 如果这些端口有服务在监听，很可疑。
 * ============================================================ */
static int detect_debug_ports(void) {
    static const int ports[] = {27042, 27043, 8600, 8700, 0};

    for (int i = 0; ports[i]; i++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) continue;

        /* 设置 200ms 超时（不要等太久） */
        struct timeval tv = {0, 200000};
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(ports[i]);
        addr.sin_addr.s_addr = htonl(0x7F000001);  /* 127.0.0.1 */

        int ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
        close(fd);

        if (ret == 0) {
            __android_log_print(ANDROID_LOG_WARN, TAG,
                                "port %d is open (suspicious)", ports[i]);
            return 1;
        }
    }

    return 0;
}

/* ============================================================
 * 综合检测入口
 * ============================================================ */
int fy_anti_debug_check(void) {
    //if (detect_ptrace())      return 1;  // 在某些设备上误报
    if (detect_tracer_pid())  return 1;
    if (detect_debug_libs())  return 1;
    if (detect_timing())      return 1;
    if (detect_signal_debug())return 1;
    if (detect_debug_ports()) return 1;
    return 0;
}

/* ============================================================
 * 后台监控线程
 *
 * 每 3 秒执行一次综合检测。
 * 连续 2 次检测到调试 → 确认被调试 → 终止进程。
 *
 * 使用连续确认机制防止误报（如时序检测的偶发异常）。
 * ============================================================ */
static volatile int g_monitor_running = 0;

static void *monitor_thread(void *arg) {
    (void)arg;

    int consecutive_fails = 0;

    while (g_monitor_running) {
        sleep(3);

        if (fy_anti_debug_check()) {
            consecutive_fails++;
            __android_log_print(ANDROID_LOG_WARN, TAG,
                                "debug check failed (%d consecutive)",
                                consecutive_fails);

            if (consecutive_fails >= 2) {
                __android_log_print(ANDROID_LOG_ERROR, TAG,
                                    "debugger confirmed, terminating process");
                /* 直接 kill，不给调试器反应时间 */
                raise(SIGKILL);
            }
        } else {
            consecutive_fails = 0;  /* 重置计数 */
        }
    }

    return NULL;
}

/**
 * 启动反调试监控
 * 在 JNI_OnLoad 中调用一次，后续持续运行
 */
void fy_start_anti_debug_monitor(void) {
    if (g_monitor_running) return;

    g_monitor_running = 1;
    pthread_t tid;
    pthread_create(&tid, NULL, monitor_thread, NULL);
    pthread_detach(tid);

    __android_log_print(ANDROID_LOG_INFO, TAG,
                        "anti-debug monitor started (interval: 3s)");
}
