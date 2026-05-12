//
// Created by 方方大王 on 2026/5/13.
//

/*
 * page.h — 16KB 页面兼容层
 *
 * 背景：
 *   Android 15 (API 35) 引入 16KB 页面支持。
 *   Android 17 部分设备/模拟器强制使用 16KB 页面。
 *   如果 .so 的 ELF segment 按 4KB 对齐，dlopen 会失败：
 *     "program alignment (4096) cannot be smaller than system page size (16384)"
 *   如果 mprotect 的地址没有按页面大小对齐，会 SIGSEGV：
 *     "SEGV_ACCERR" (write to misaligned page)
 *
 * 本文件提供的工具函数确保所有内存操作按实际页面大小对齐。
 *
 * 核心原则：永远不硬编码 4096，永远用 sysconf(_SC_PAGESIZE)。
 */
#ifndef FY_PAGE_H
#define FY_PAGE_H

#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>
#include <android/log.h>

#define FY_PAGE_TAG "FY_PAGE"

/* 全局缓存的页面大小（运行时只查询一次） */
static long g_fy_page_size = 0;

/**
 * 获取系统页面大小
 *
 * 在 4KB 页面设备上返回 4096
 * 在 16KB 页面设备上返回 16384
 *
 * 使用 __builtin_expect 提示编译器：首次调用是罕见路径
 */
static inline long fy_page_size(void) {
    if (__builtin_expect(g_fy_page_size == 0, 0)) {
        g_fy_page_size = sysconf(_SC_PAGESIZE);
        __android_log_print(ANDROID_LOG_INFO, FY_PAGE_TAG,
                            "system page size: %ld bytes", g_fy_page_size);
    }
    return g_fy_page_size;
}

/**
 * 将地址向下对齐到页面边界
 *
 * 例: 地址 0x70001234, 页大小 16384 (0x4000)
 *   → 结果 0x70000000
 */
static inline uintptr_t fy_page_start(uintptr_t addr) {
    long ps = fy_page_size();
    return addr & ~((uintptr_t)ps - 1);
}

/**
 * 将长度向上对齐到页面边界（考虑起始地址的偏移）
 *
 * 例: 地址 0x70001234, 长度 100, 页大小 16384
 *   → page_start = 0x70000000
 *   → 偏移 = 0x1234 = 4660
 *   → 总长度 = 4660 + 100 = 4760
 *   → 向上对齐 = 16384
 */
static inline size_t fy_page_align(size_t len, uintptr_t addr) {
    long ps = fy_page_size();
    uintptr_t start = fy_page_start(addr);
    size_t total = len + (size_t)(addr - start);
    return (total + (size_t)ps - 1) & ~((size_t)ps - 1);
}

/**
 * 安全的 mprotect —— 按系统页大小自动对齐
 *
 * 这个函数是修复 Android 17 SEGV_ACCERR 崩溃的关键。
 *
 * 原始 mprotect 要求：
 *   addr 必须是页对齐的
 *   len 必须是页大小的倍数
 *
 * 如果不满足 → 返回 EINVAL 或触发 SEGV_ACCERR
 *
 * 本函数自动处理对齐，调用者无需关心页面大小。
 *
 * @param addr  任意地址（不要求对齐）
 * @param len   任意长度（不要求对齐）
 * @param prot  保护标志 (PROT_READ, PROT_WRITE, PROT_EXEC)
 * @return 0 成功, -1 失败
 */
static inline int fy_mprotect(void *addr, size_t len, int prot) {
    uintptr_t start = fy_page_start((uintptr_t)addr);
    size_t aligned_len = fy_page_align(len, (uintptr_t)addr);
    int ret = mprotect((void *)start, aligned_len, prot);
    if (ret != 0) {
        __android_log_print(ANDROID_LOG_WARN, FY_PAGE_TAG,
                            "mprotect failed: addr=%p len=%zu prot=%d "
                            "(aligned: start=%p len=%zu)",
                            addr, len, prot, (void *)start, aligned_len);
    }
    return ret;
}

/**
 * 分配可执行内存（16K 页面兼容）
 *
 * 用于 SO 代码段解密后的运行空间。
 * mmap 返回的地址天然按页面大小对齐，无需手动对齐。
 *
 * 注意：MAP_ANONYMOUS | PROT_EXEC 在某些设备上可能受限。
 * 如果 mmap 失败，可能是 SELinux 策略阻止了匿名可执行内存。
 *
 * @param size 需要的字节数（会向上对齐到页大小）
 * @return 可执行内存指针，失败返回 NULL
 */
static inline void *fy_mmap_exec(size_t size) {
    /* 向上对齐到页大小 */
    size_t aligned = fy_page_align(size, 0);

    void *p = mmap(NULL, aligned,
                   PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS,
                   -1, 0);

    if (p == MAP_FAILED) {
        __android_log_print(ANDROID_LOG_ERROR, FY_PAGE_TAG,
                            "mmap exec failed: requested=%zu aligned=%zu", size, aligned);
        return NULL;
    }

    __android_log_print(ANDROID_LOG_INFO, FY_PAGE_TAG,
                        "mmap exec: %zu bytes at %p", aligned, p);
    return p;
}

/**
 * 安全释放 mmap 分配的内存
 */
static inline void fy_munmap(void *addr, size_t size) {
    if (addr && addr != MAP_FAILED) {
        size_t aligned = fy_page_align(size, (uintptr_t)addr);
        munmap(addr, aligned);
    }
}

#endif /* FY_PAGE_H */
