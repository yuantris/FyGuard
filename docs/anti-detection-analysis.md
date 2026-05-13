# 反调试与反Frida检测问题分析

## 概述

本文档记录了 FY Guard 加固方案中反调试和反Frida检测功能的测试结果和问题分析。

## 反调试检测 (anti_debug.c)

### 检测方法列表

| 方法 | 函数名 | 状态 | 说明 |
|------|--------|------|------|
| ptrace自附加 | `detect_ptrace()` | ❌ 已禁用 | 在某些Android设备上因权限限制误报 |
| TracerPid检测 | `detect_tracer_pid()` | ✅ 正常 | 读取`/proc/self/status`中的TracerPid字段 |
| 调试库扫描 | `detect_debug_libs()` | ✅ 正常 | 扫描`/proc/self/maps`查找调试工具库 |
| 时序检测 | `detect_timing()` | ✅ 正常 | 检测单步调试导致的执行时间异常 |
| 信号陷阱 | `detect_signal_debug()` | ✅ 正常 | 检测SIGTRAP是否被调试器拦截 |
| 调试端口扫描 | `detect_debug_ports()` | ✅ 正常 | 扫描JDWP/Frida默认端口 |

### 问题详情

#### 1. detect_ptrace 误报

**问题描述：**
`ptrace(PTRACE_ATTACH)` 在某些 Android 设备上因 SELinux 权限限制会失败，导致误报为调试器存在。

**错误日志：**
```
FY_ANTIDBG: ptrace: debugger detected
```

**原因分析：**
- Android 10+ 引入了更严格的 SELinux 策略
- 非 root 环境下，子进程 ptrace 父进程可能被拒绝
- 即使没有调试器，attach 也会失败

**解决方案：**
禁用 `detect_ptrace`，改用 `detect_tracer_pid` 作为主要检测手段。

```c
int fy_anti_debug_check(void) {
    //if (detect_ptrace())      return 1;  // 在某些设备上误报
    if (detect_tracer_pid())  return 1;
    if (detect_debug_libs())  return 1;
    if (detect_timing())      return 1;
    if (detect_signal_debug())return 1;
    if (detect_debug_ports()) return 1;
    return 0;
}
```

---

## 反Frida检测 (anti_frida.c)

### 检测方法列表

| 方法 | 函数名 | 状态 | 说明 |
|------|--------|------|------|
| maps文件扫描 | `scan_maps_for_frida()` | ✅ 正常 | 扫描`/proc/self/maps`查找frida-agent等特征 |
| Frida端口扫描 | `scan_frida_ports()` | ✅ 正常 | 扫描Frida默认端口(27042等) |
| Frida管道扫描 | `scan_frida_pipes()` | ✅ 正常 | 检测`/proc/self/fd`中的Frida管道 |
| 内存特征扫描 | `scan_memory_pattern()` | ❌ 已禁用 | 直接访问内存地址触发SIGBUS |
| 异常进程检测 | `detect_abnormal_process()` | ✅ 正常 | 检测frida-server等进程 |
| Frida线程检测 | `detect_frida_threads()` | ✅ 正常 | 扫描`/proc/self/task`查找Frida线程名 |
| Xposed类检测 | `detect_xposed_classes()` | ✅ 正常 | 通过JNI FindClass检测Xposed框架 |

### 问题详情

#### 1. scan_memory_pattern 崩溃

**问题描述：**
直接读取内存地址搜索"LIBFRIDA"特征时，访问未映射或权限不足的内存区域，触发SIGBUS信号导致应用崩溃。

**错误日志：**
```
libc    : Fatal signal 7 (SIGBUS), code 2 (BUS_ADRERR), fault addr 0x78848db000
DEBUG   : signal 7 (SIGBUS), code 2 (BUS_ADRERR), fault addr 0x00000078848db000
```

**原因分析：**
- `/proc/self/maps` 中的内存区域可能：
  - 在读取时被取消映射
  - 权限发生变化
  - 地址范围不准确
- 直接指针访问 `(const uint8_t *)start` 没有错误处理

**问题代码：**
```c
static int scan_memory_pattern(void) {
    // ...
    const uint8_t *mem = (const uint8_t *)start;
    for (size_t off = 0; off + 8 < region_size; off += 4096) {
        if (memcmp(mem + off, "LIBFRIDA", 8) == 0) {  // 可能触发SIGBUS
            // ...
        }
    }
    // ...
}
```

**解决方案：**
禁用 `scan_memory_pattern`，依赖其他更安全的检测方法。

```c
int fy_anti_frida_check(JNIEnv *env) {
    if (scan_maps_for_frida())   return 1;
    if (scan_frida_ports())      return 1;
    if (scan_frida_pipes())      return 1;
    //if (scan_memory_pattern())   return 1;  // 可能触发SIGBUS
    if (detect_abnormal_process()) return 1;
    if (detect_frida_threads())  return 1;
    if (env && detect_xposed_classes(env)) return 1;
    return 0;
}
```

**改进建议（未实现）：**
如果需要启用内存扫描，应使用 `mincore()` 系统调用或 `mprotect()` 配合信号处理来安全访问内存。

---

## 测试环境

- 设备：小米平板
- Android版本：14
- 测试日期：2026-05-14

## 测试结果

启用所有可用检测后，应用正常运行：

```
FY_ANTIDBG: anti-debug monitor started (interval: 3s)
MyApp   : securityCheck: result = 0
MyApp   : getPageInfo: result = pageSize=4096, maxPageAlign=16384, mmapExec=true
```

## 当前检测策略

### 反调试检测（5种）
1. TracerPid检测 - 可靠
2. 调试库扫描 - 可靠
3. 时序检测 - 可靠
4. 信号陷阱 - 可靠
5. 调试端口扫描 - 可靠

### 反Frida/Xposed检测（6种）
1. maps文件扫描 - 可靠
2. Frida端口扫描 - 可靠
3. Frida管道扫描 - 可靠
4. 异常进程检测 - 可靠
5. Frida线程检测 - 可靠
6. Xposed类检测 - 可靠

---

## 附录：检测原理简述

### detect_tracer_pid
Linux内核在 `/proc/[pid]/status` 中记录 `TracerPid` 字段：
- 被调试时：TracerPid = 调试器PID
- 正常运行：TracerPid = 0

### detect_debug_libs
扫描 `/proc/self/maps` 查找调试工具注入的库：
- `libandroidhook.so` (Xposed)
- `libfrida-agent.so` (Frida)
- `libhook.so`, `libsubstrate.so` 等

### detect_timing
测量一段代码的执行时间，单步调试会导致明显的时间异常。

### detect_signal_debug
发送 `SIGTRAP` 信号，如果被调试器拦截则说明正在被调试。

### detect_debug_ports
尝试连接常见的调试端口：
- JDWP: 5005, 8700, 9300 等
- Frida: 27042, 27043 等

### scan_maps_for_frida
扫描 `/proc/self/maps` 查找：
- `frida-agent`
- `frida-gadget`
- `frida-server`
- `linjector`

### scan_frida_pipes
扫描 `/proc/self/fd` 查找 Frida 通信管道特征。

### detect_frida_threads
扫描 `/proc/self/task/[tid]/comm` 查找 Frida 线程名：
- `gmain` (GLib main loop)
- `gum-js-loop` (Frida JS runtime)

### detect_xposed_classes
通过 JNI `FindClass` 尝试加载 Xposed 框架类：
- `de/robv/android/xposed/XposedBridge`
- `de/robv/android/xposed/XC_MethodHook`
