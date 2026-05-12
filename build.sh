#!/bin/bash
# ============================================================
# FY Guard 一键构建脚本
#
# 执行流程：
#   1. 编译 guard-native → libfyencrypt.so
#   2. 编译 guard-stub   → stub classes.dex
#   3. 复制产物到 buildSrc/resources（插件内置资源）
#   4. 执行 assembleRelease + hardenRelease
#
# 前置条件：
#   - ANDROID_HOME 环境变量已设置
#   - NDK 已安装（通过 SDK Manager）
#   - Java 17+
# ============================================================
set -e

echo ""
echo "╔═══════════════════════════════════════════╗"
echo "║         FY Guard - Build & Harden         ║"
echo "╚═══════════════════════════════════════════╝"
echo ""

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_DIR"

# ----------------------------------------------------------
# Step 1: 编译 Native 壳库
# ----------------------------------------------------------
echo "[1/4] Building native library (libfyencrypt.so)..."
./gradlew :guard-native:assembleRelease 2>&1 | tail -5

SO_PATH="guard-native/build/intermediates/cmake/release/obj/arm64-v8a/libfyencrypt.so"
if [ ! -f "$SO_PATH" ]; then
    echo "[!] ERROR: libfyencrypt.so not found at $SO_PATH"
    echo "    Check NDK installation and CMake build output"
    exit 1
fi
SO_SIZE=$(stat -f%z "$SO_PATH" 2>/dev/null || stat -c%s "$SO_PATH" 2>/dev/null)
echo "[+] libfyencrypt.so OK ($SO_SIZE bytes)"

# ----------------------------------------------------------
# Step 2: 编译 Stub DEX
# ----------------------------------------------------------
echo ""
echo "[2/4] Building stub classes.dex..."
./gradlew :guard-stub:assembleRelease 2>&1 | tail -5

AAR_PATH="guard-stub/build/outputs/aar/guard-stub-release.aar"
if [ ! -f "$AAR_PATH" ]; then
    echo "[!] ERROR: Stub AAR not found at $AAR_PATH"
    exit 1
fi

# 从 AAR 中提取 classes.jar，用 d8 转为 classes.dex
WORK_DIR="$PROJECT_DIR/build/stub_work"
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR/dex"

echo "    extracting classes.jar from AAR..."
unzip -o "$AAR_PATH" classes.jar -d "$WORK_DIR"

# 查找 d8 工具
D8_PATH=""
for bt in "$ANDROID_HOME"/build-tools/*/; do
    if [ -f "${bt}d8" ] || [ -f "${bt}d8.bat" ]; then
        D8_PATH="${bt}d8"
    fi
done
if [ -z "$D8_PATH" ]; then
    echo "[!] ERROR: d8 not found in $ANDROID_HOME/build-tools/"
    exit 1
fi

echo "    converting to DEX with d8..."
"$D8_PATH" --min-api 29 --output "$WORK_DIR/dex" "$WORK_DIR/classes.jar"

if [ ! -f "$WORK_DIR/dex/classes.dex" ]; then
    echo "[!] ERROR: d8 did not produce classes.dex"
    exit 1
fi
echo "[+] stub classes.dex OK"

# ----------------------------------------------------------
# Step 3: 复制产物到 buildSrc/resources
# ----------------------------------------------------------
echo ""
echo "[3/4] Copying artifacts to plugin resources..."
RES_DIR="guard-plugin/src/main/resources"
mkdir -p "$RES_DIR/stub"
mkdir -p "$RES_DIR/native/arm64-v8a"

cp "$WORK_DIR/dex/classes.dex" "$RES_DIR/stub/classes.dex"
cp "$SO_PATH" "$RES_DIR/native/arm64-v8a/libfyencrypt.so"

echo "    stub/classes.dex     -> $(stat -c%s "$RES_DIR/stub/classes.dex" 2>/dev/null || stat -f%z "$RES_DIR/stub/classes.dex") bytes"
echo "    native/libfyencrypt.so -> $(stat -c%s "$RES_DIR/native/arm64-v8a/libfyencrypt.so" 2>/dev/null || stat -f%z "$RES_DIR/native/arm64-v8a/libfyencrypt.so") bytes"
echo "[+] Done"

# ----------------------------------------------------------
# Step 4: 构建加固 APK
# ----------------------------------------------------------
echo ""
echo "[4/4] Building hardened APK..."
./gradlew :app:assembleRelease :app:hardenRelease 2>&1 | tail -10

# 输出结果
APK_DIR="app/build/outputs/apk/release"
if ls "$APK_DIR"/*hardened*.apk 1>/dev/null 2>&1; then
    HARDENED=$(ls "$APK_DIR"/*hardened*.apk | head -1)
    echo ""
    echo "╔═══════════════════════════════════════════╗"
    echo "║  BUILD SUCCESS                            ║"
    echo "║                                           ║"
    echo "║  Hardened APK: $HARDENED"
    echo "║                                           ║"
    echo "║  Don't forget to sign with apksigner!     ║"
    echo "╚═══════════════════════════════════════════╝"
else
    echo "[!] No hardened APK found in $APK_DIR"
    echo "    Check build output for errors"
fi
