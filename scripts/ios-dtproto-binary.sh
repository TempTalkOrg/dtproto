#!/usr/bin/env bash
#
# dtproto iOS 构建脚本
#
# 一键完成: cargo clean → 交叉编译 3 个 target → lipo 合并模拟器 → 生成 Swift/Header → 打 zip 包
#
# 用法: bash scripts/ios-dtproto-binary.sh
# 从项目根目录执行，也可从任意位置执行（脚本自动定位项目根）
#
# 产物目录结构 (对齐 TempTalk-iOS 工程):
#   iOS/DTProto/libdtproto_ffi/libdtproto_ffi_<VERSION>/iphoneos/libdtproto_ffi.a
#   iOS/DTProto/libdtproto_ffi/libdtproto_ffi_<VERSION>/iphonesimulator/libdtproto_ffi.a
#   iOS/DTProto/dtproto.swift
#   iOS/DTProto/dtprotoFFI/dtprotoFFI.h
#
# zip 包名: libdtproto_ffi_<VERSION>.zip
# S3 上传: https://difft-proto-binary.s3.ap-southeast-1.amazonaws.com/libdtproto_ffi_<VERSION>.zip
#
set -euo pipefail

PROJECTPATH="$(cd "$(dirname "$0")/.." && pwd)"
cd "${PROJECTPATH}"

VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')
PACKAGE_NAME="dtproto_ffi"
LIB_TARGET_NAME="uniffi_dtproto"
COMPILED_LIB_NAME="lib${LIB_TARGET_NAME}"
OUTPUT_LIB_NAME="libdtproto_ffi"
IOS_PATH="${PROJECTPATH}/iOS/DTProto"
TARGET_PATH="${PROJECTPATH}/target"
SRC_PATH="${PROJECTPATH}/src"
LIB_ROOT="${IOS_PATH}/${OUTPUT_LIB_NAME}"
LIB_VER_DIR="${LIB_ROOT}/${OUTPUT_LIB_NAME}_${VERSION}"
IPHONEOS_DIR="${LIB_VER_DIR}/iphoneos"
SIMULATOR_DIR="${LIB_VER_DIR}/iphonesimulator"
ZIP_NAME="${OUTPUT_LIB_NAME}_${VERSION}.zip"

echo "=========================================="
echo "  dtproto ${VERSION} iOS 构建"
echo "=========================================="

# Step 0: 清理 Rust 编译缓存
echo ""
echo "[0/5] 清理 Rust 编译缓存..."
cargo clean
echo "  ✓ cargo clean 完成"

# Step 1: 生成 Swift 绑定和 C Header
echo ""
echo "[1/5] 生成 Swift 绑定和 C Header..."
cargo run --release --bin uniffi-bindgen generate "${SRC_PATH}/dtproto.udl" --language swift
echo "  ✓ Swift/Header 生成完成"

# Step 2: 交叉编译三个 iOS target (release)
echo ""
echo "[2/5] 编译 aarch64-apple-ios (真机 arm64)..."
cargo rustc -p ${PACKAGE_NAME} --lib --crate-type staticlib --release --target aarch64-apple-ios
echo "  ✓ 真机 arm64"

echo ""
echo "[3/5] 编译 aarch64-apple-ios-sim (模拟器 arm64)..."
cargo rustc -p ${PACKAGE_NAME} --lib --crate-type staticlib --release --target aarch64-apple-ios-sim
echo "  ✓ 模拟器 arm64"

echo ""
echo "[4/5] 编译 x86_64-apple-ios (模拟器 x86_64)..."
cargo rustc -p ${PACKAGE_NAME} --lib --crate-type staticlib --release --target x86_64-apple-ios
echo "  ✓ 模拟器 x86_64"

# Step 5: 合并产物
echo ""
echo "[5/5] 合并产物..."

DEVICE_LIB="${TARGET_PATH}/aarch64-apple-ios/release/${COMPILED_LIB_NAME}.a"
SIM_ARM64_LIB="${TARGET_PATH}/aarch64-apple-ios-sim/release/${COMPILED_LIB_NAME}.a"
SIM_X86_LIB="${TARGET_PATH}/x86_64-apple-ios/release/${COMPILED_LIB_NAME}.a"

# 清理旧产物目录
rm -rf "${LIB_VER_DIR}"
mkdir -p "${IPHONEOS_DIR}"
mkdir -p "${SIMULATOR_DIR}"

# 5a: 真机 .a
cp "${DEVICE_LIB}" "${IPHONEOS_DIR}/${OUTPUT_LIB_NAME}.a"
echo "  ✓ iphoneos/${OUTPUT_LIB_NAME}.a"

# 5b: lipo 合并模拟器 fat binary
lipo -create "${SIM_ARM64_LIB}" "${SIM_X86_LIB}" \
     -output "${SIMULATOR_DIR}/${OUTPUT_LIB_NAME}.a"
echo "  ✓ iphonesimulator/${OUTPUT_LIB_NAME}.a (arm64 + x86_64)"

# 5c: 复制 Swift 绑定和 C Header
mv "${SRC_PATH}/dtproto.swift" "${IOS_PATH}/dtproto.swift"
mv "${SRC_PATH}/dtprotoFFI.h" "${IOS_PATH}/dtprotoFFI/dtprotoFFI.h"
rm -f "${SRC_PATH}/dtprotoFFI.modulemap"
echo "  ✓ Swift 绑定和 Header 已更新"

# 5d: 打 zip 包
cd "${LIB_ROOT}"
rm -f "${ZIP_NAME}"
zip -r "${ZIP_NAME}" "${OUTPUT_LIB_NAME}_${VERSION}/"
echo "  ✓ ${ZIP_NAME}"

# 验证产物
echo ""
echo "=========================================="
echo "  构建完成！产物验证："
echo "=========================================="
echo ""

DEVICE_SIZE=$(wc -c < "${IPHONEOS_DIR}/${OUTPUT_LIB_NAME}.a" | tr -d ' ')
SIM_SIZE=$(wc -c < "${SIMULATOR_DIR}/${OUTPUT_LIB_NAME}.a" | tr -d ' ')
ZIP_SIZE=$(wc -c < "${LIB_ROOT}/${ZIP_NAME}" | tr -d ' ')
echo "  iphoneos .a:       ${DEVICE_SIZE} bytes"
echo "  iphonesimulator .a: ${SIM_SIZE} bytes"
echo "  ${ZIP_NAME}: ${ZIP_SIZE} bytes"
echo "  dtproto.swift:     $(wc -l < "${IOS_PATH}/dtproto.swift" | tr -d ' ') lines"
echo "  dtprotoFFI.h:      $(wc -l < "${IOS_PATH}/dtprotoFFI/dtprotoFFI.h" | tr -d ' ') lines"
echo ""

echo "  模拟器 fat 架构:"
lipo -info "${SIMULATOR_DIR}/${OUTPUT_LIB_NAME}.a"
echo ""

echo "下一步:"
echo "  上传 ${LIB_ROOT}/${ZIP_NAME}"
echo "  到 S3: https://difft-proto-binary.s3.ap-southeast-1.amazonaws.com/${ZIP_NAME}"
