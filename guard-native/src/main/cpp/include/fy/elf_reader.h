//
// Created by 方方大王 on 2026/5/13.
//
/*
 * elf_reader.h — 运行时 ELF 解析
 *
 * 功能：
 *   1. 从 /proc/self/maps 定位自身 .so 的内存映射
 *   2. 解析 ELF section header，找到自定义 section（如 .fytext）
 *   3. 获取函数在 .so 中的偏移地址
 *
 * 用途：
 *   - SO 多层壳：从自身 .so 中读取加密的 .fytext section
 *   - GOT 解析：解析 .got / .plt section
 */
#ifndef FY_ELF_READER_H
#define FY_ELF_READER_H

#include <stdint.h>
#include <string.h>
#include <elf.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <android/log.h>

#define FY_ELF_TAG "FY_ELF"

/**
 * Section 信息
 */
typedef struct {
    const char *name;      // section 名称
    const uint8_t *data;   // section 在内存中的地址
    size_t size;           // section 大小
} fy_section_t;

/**
 * 在已加载的 .so 中查找指定 section
 *
 * 原理：
 *   动态链接器（linker64）将整个 .so 文件 mmap 到内存中。
 *   虽然执行时只关心 LOAD segment，但 section header table
 *   仍然在内存中可读（因为它在文件末尾，被 mmap 映射了）。
 *
 * 注意：
 *   如果 .so 是 strip 过的（去掉了 section header），
 *   这个函数会返回 -1。但我们编译时设置了 --strip-all，
 *   只剥离符号表，不剥离 section header。
 *
 * @param base   .so 在内存中的基地址（ElfW(Addr)）
 * @param target 目标 section 名称
 * @param out    输出 section 信息
 * @return 0 成功, -1 未找到
 */
static int fy_find_section(void *base, const char *target, fy_section_t *out) {
    ElfW(Ehdr) *ehdr = (ElfW(Ehdr) *)base;

    /* 校验 ELF magic: 0x7F 'E' 'L' 'F' */
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        __android_log_print(ANDROID_LOG_ERROR, FY_ELF_TAG, "not a valid ELF");
        return -1;
    }

    /* 获取 section header table */
    ElfW(Shdr) *shdrs = (ElfW(Shdr) *)((uintptr_t)base + ehdr->e_shoff);

    /* 获取 section name string table */
    if (ehdr->e_shstrndx >= ehdr->e_shnum) return -1;
    ElfW(Shdr) *shstrtab = &shdrs[ehdr->e_shstrndx];
    const char *strtab = (const char *)((uintptr_t)base + shstrtab->sh_offset);

    /* 遍历所有 section */
    for (int i = 0; i < ehdr->e_shnum; i++) {
        const char *name = strtab + shdrs[i].sh_name;
        if (strcmp(name, target) == 0) {
            out->name = name;
            out->data = (const uint8_t *)((uintptr_t)base + shdrs[i].sh_offset);
            out->size = shdrs[i].sh_size;

            __android_log_print(ANDROID_LOG_INFO, FY_ELF_TAG,
                                "found section '%s': offset=0x%lx size=%zu",
                                name, (unsigned long)shdrs[i].sh_offset, out->size);
            return 0;
        }
    }

    __android_log_print(ANDROID_LOG_WARN, FY_ELF_TAG,
                        "section '%s' not found", target);
    return -1;
}

/**
 * 获取自身 .so 的基地址
 *
 * 使用 dladdr 获取包含指定函数的 .so 信息。
 * dli_fbase 就是 .so 的加载基地址。
 *
 * @param any_func_in_so .so 中任意一个函数的地址
 * @return .so 的基地址，失败返回 NULL
 */
static void *fy_self_base(void *any_func_in_so) {
    Dl_info info;
    if (dladdr(any_func_in_so, &info) == 0) return NULL;
    return (void *)info.dli_fbase;
}

/**
 * 从自身 .so 中读取加密 section 的数据
 *
 * 先尝试从内存映射中读取（快，不涉及文件 I/O）。
 * 如果 section header 不存在（被 strip 了），返回 NULL。
 *
 * @param base        .so 基地址
 * @param section_name 目标 section 名称
 * @param out_size    输出数据大小
 * @return 分配的缓冲区（调用者需 free），失败返回 NULL
 */
static uint8_t *fy_read_encrypted_section(void *base, const char *section_name,
                                          size_t *out_size) {
    fy_section_t sec;
    if (fy_find_section(base, section_name, &sec) != 0) {
        return NULL;
    }

    /* 复制到堆内存（避免 section 指针在 SO 被卸载后失效） */
    uint8_t *buf = (uint8_t *)malloc(sec.size);
    if (!buf) {
        __android_log_print(ANDROID_LOG_ERROR, FY_ELF_TAG,
                            "malloc(%zu) failed", sec.size);
        return NULL;
    }
    memcpy(buf, sec.data, sec.size);
    *out_size = sec.size;
    return buf;
}

#endif /* FY_ELF_READER_H */

