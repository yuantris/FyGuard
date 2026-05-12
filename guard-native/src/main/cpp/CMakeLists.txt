cmake_minimum_required(VERSION 3.22)
project(fy_guard C)

# ============================================================
# 16KB 页面对齐 —— 这是解决 Android 17 崩溃的核心
#
# max-page-size:    ELF segment 的最大对齐粒度
# common-page-size: 运行时常用页大小
#
# 设置为 16384 后，ELF 的 LOAD segment 会按 16KB 对齐，
# 在 4KB 和 16KB 页面的设备上都能正常 dlopen。
#
# 如果不设置，默认 4096，在 16KB 页面设备上会报：
#   "program alignment (4096) cannot be smaller than system page size (16384)"
# ============================================================
add_link_options(
    -Wl,-z,max-page-size=16384
    -Wl,-z,common-page-size=16384
)

# ============================================================
# 源文件列表
# ============================================================
set(SRC src)

set(SOURCES
    ${SRC}/entry.c              # JNI_OnLoad 总入口，初始化调度
    ${SRC}/anti_debug.c         # 反调试矩阵（6 种检测）
    ${SRC}/anti_frida.c         # 反 Frida / Xposed（7 种检测）
    ${SRC}/integrity.c          # APK 签名完整性校验
    ${SRC}/dex_guard.c          # DEX 解密加载 + ClassLoader 创建
    ${SRC}/method_restore.c     # 函数抽取运行时还原引擎
    ${SRC}/vm_engine.c          # VMP 自定义字节码解释器
    ${SRC}/so_loader.c          # SO 多层壳 loader + GOT 解析
    ${SRC}/asset_decrypt.c      # 运行时资源按需解密
    ${SRC}/jni_bridge.c         # JNI 方法注册
)

# 编译为共享库 libfyencrypt.so
add_library(fyencrypt SHARED ${SOURCES})

# 头文件搜索路径
target_include_directories(fyencrypt PRIVATE
    include
)

# 系统库依赖
find_library(log-lib log)           # Android 日志 (__android_log_print)
target_link_libraries(fyencrypt
    ${log-lib}                      # 日志
    dl                              # dlopen / dlsym / dladdr
    android                         # AAssetManager (读取 assets)
)

# ============================================================
# 编译选项
# ============================================================
target_compile_options(fyencrypt PRIVATE
    -Wall -Wextra -O2               # 警告 + 优化
    -ffunction-sections             # 每个函数独立 section（配合 gc-sections 裁剪）
    -fdata-sections                 # 每个数据独立 section
    -fvisibility=hidden             # 默认隐藏所有符号
    -fstack-protector-strong        # 栈保护
)

# ============================================================
# 链接选项
# ============================================================
target_link_options(fyencrypt PRIVATE
    -Wl,--gc-sections               # 删除未引用的 section（减小体积）
    -Wl,--strip-all                 # 剥离所有符号（增加逆向难度）
)

# SO 文件属性
set_target_properties(fyencrypt PROPERTIES
    C_VISIBILITY_PRESET hidden      # 隐藏符号
)

# ============================================================
# 密钥注入
# 从 Gradle 通过 -DFY_MASTER_KEY=xxx 传入
# native 层用此密钥派生 DEX / SO / 资源的子密钥
# ============================================================
if(DEFINED FY_MASTER_KEY AND NOT FY_MASTER_KEY STREQUAL "")
    target_compile_definitions(fyencrypt PRIVATE
        FY_MASTER_KEY_HEX="${FY_MASTER_KEY}"
    )
    message(STATUS "[FY Guard] Master key injected via CMake")
else()
    message(WARNING "[FY Guard] No master key defined, using default placeholder")
    target_compile_definitions(fyencrypt PRIVATE
        FY_MASTER_KEY_HEX="a3f1b8c92d4e6f0112233445566778899aabbccddeeff00112233445566778899"
    )
endif()