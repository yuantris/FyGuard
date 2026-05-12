//
// Created by 方方大王 on 2026/5/13.
//
/*
 * so_loader.c — SO 多层壳 Loader + GOT/PLT 动态解析
 *
 * 与 buildSrc SoLayerBuilder 配合工作。
 *
 * 架构：
 *   __attribute__((constructor))
 *   → Layer 1: 读取 .so 文件尾部的 trailer
 *   → 找到加密的 .fytext section 数据
 *   → AES-256 解密
 *   → mmap 新的可执行内存（16K 页面对齐！）
 *   → 设置 R-X 权限
 *   → 函数指针重定向
 *
 * 16K 兼容的关键设计：
 *   - 永远不修改原始 .so 的 .text 段
 *   - 所有解密后的代码放在 mmap 新分配的内存中
 *   - mmap 的地址天然按系统页大小对齐
 *   - 这完全避免了 mprotect 对齐导致的 SEGV_ACCERR
 */
#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <elf.h>
#include <link.h>
#include "fy/page.h"
#include "fy/crypto.h"

#define TAG "FY_SOLOADER"

/* .fytext section 的魔数（与 buildSrc SoLayerBuilder 一致） */
#define FYTEXT_MAGIC 0x54594646  /* "FYT\0" */

/* ============================================================
 * Loader 状态
 * ============================================================ */
typedef struct {
    void   *decrypted_code;   /* 解密后的代码（mmap 分配） */
    size_t  code_size;        /* 代码大小 */
    void   *so_base;          /* .so 的加载基地址 */
    int     initialized;
} so_loader_state_t;

static so_loader_state_t g_state = {0};

/* ============================================================
 * 构造函数（SO 加载时自动执行）
 * ============================================================ */
__attribute__((constructor))
static void fy_so_loader_init(void) {
    if (g_state.initialized) return;

    /* 1. 初始化页面大小 */
    fy_page_size();

    __android_log_print(ANDROID_LOG_INFO, TAG,
                        "SO loader: initializing...");

    /* 2. 获取自身基地址 */
    Dl_info info;
    if (dladdr((void *)fy_so_loader_init, &info) == 0) {
        __android_log_print(ANDROID_LOG_WARN, TAG,
                            "dladdr failed, cannot locate SO base");
        return;
    }

    g_state.so_base = (void *)info.dli_fbase;

    __android_log_print(ANDROID_LOG_INFO, TAG,
                        "SO base: %p", g_state.so_base);

    /* 3. 检查是否有 .fytext section（代码段加密数据） */
    /*
     * 注意：完整实现需要从 ELF section header 读取 .fytext，
     * 或者从文件尾部的 trailer 读取加密数据。
     * 这里演示完整流程。
     *
     * 生产环境还需要：
     *   - 解析 trailer（magic + offset + size）
     *   - 读取加密数据
     *   - AES 解密
     *   - mmap 可执行内存
     *   - 复制解密后的代码
     *   - 设置 R-X 权限
     */

    g_state.initialized = 1;

    __android_log_print(ANDROID_LOG_INFO, TAG,
                        "SO loader: initialized successfully");
}

/* ============================================================
 * GOT/PLT 动态解析
 *
 * 不依赖标准 PLT，运行时通过 dlsym 手动解析符号。
 *
 * 好处：
 *   1. 导入表可以为空或被混淆（静态分析看不到调用了什么外部函数）
 *   2. 可以在运行时动态决定符号来源
 *   3. 可以对符号名进行混淆（运行时还原再 dlsym）
 * ============================================================ */

/**
 * 运行时符号解析
 *
 * @param lib_name 库名（如 "liblog.so"），NULL 表示搜索所有已加载库
 * @param sym_name 符号名（如 "__android_log_print"）
 * @return 函数地址，失败返回 NULL
 */
void *fy_resolve_symbol(const char *lib_name, const char *sym_name) {
    void *handle;

    if (lib_name) {
        /* 从指定库中查找 */
        handle = dlopen(lib_name, RTLD_NOW);
        if (!handle) {
            __android_log_print(ANDROID_LOG_ERROR, TAG,
                                "dlopen(%s) failed: %s", lib_name, dlerror());
            return NULL;
        }
    } else {
        /* RTLD_DEFAULT: 在所有已加载的库中查找 */
        handle = RTLD_DEFAULT;
    }

    void *sym = dlsym(handle, sym_name);
    if (!sym) {
        __android_log_print(ANDROID_LOG_ERROR, TAG,
                            "dlsym(%s) failed: %s", sym_name, dlerror());
    }

    return sym;
}

/**
 * 批量解析 GOT 条目
 *
 * 将 GOT 表中的占位符替换为实际的函数地址。
 * 这是 SO 多层壳的关键：解密后的代码中的 GOT 引用
 * 需要在运行时被正确重定向。
 *
 * @param got_base   GOT 表在内存中的基地址
 * @param got_count  GOT 条目数量
 * @param lib_names  每个条目对应的库名数组
 * @param sym_names  每个条目对应的符号名数组
 * @return 0 成功, -1 有符号解析失败
 */
int fy_resolve_got(void *got_base, int got_count,
                   const char **lib_names, const char **sym_names) {
    void **got = (void **)got_base;

    for (int i = 0; i < got_count; i++) {
        void *addr = fy_resolve_symbol(lib_names[i], sym_names[i]);
        if (!addr) {
            __android_log_print(ANDROID_LOG_ERROR, TAG,
                                "GOT resolve failed: [%d] %s!%s",
                                i, lib_names[i] ? lib_names[i] : "*",
                                sym_names[i]);
            return -1;
        }
        got[i] = addr;
    }

    __android_log_print(ANDROID_LOG_INFO, TAG,
                        "GOT resolved: %d entries", got_count);
    return 0;
}
