#!/usr/bin/env bash
set -e

PROJECTPATH="$(cd "$(dirname "$0")/.." && pwd)"
SRCPATH="${PROJECTPATH}/src"
TARGETPATH="${PROJECTPATH}/target"

# Gradle module paths
MODULEPATH="${PROJECTPATH}/Android/dtproto/src/main"
JNILIBSPATH="${MODULEPATH}/jniLibs"
KOTLINPATH="${MODULEPATH}/java/uniffi/dtproto"

echo "start working."

cd "${PROJECTPATH}"

# 16KB page alignment for Google Play (targetSdk 35+)
export RUSTFLAGS="${RUSTFLAGS:-} -C link-arg=-Wl,-z,max-page-size=16384"

echo "1. setup."
rustup target add aarch64-linux-android
rustup target add armv7-linux-androideabi
rustup target add x86_64-linux-android
rustup target add x86_64-apple-darwin
rustup target add x86_64-unknown-linux-gnu

echo "2. generate kotlin."

cargo run --bin uniffi-bindgen generate ${SRCPATH}/dtproto.udl --language kotlin

mkdir -p ${KOTLINPATH}
cp ${SRCPATH}/uniffi/dtproto/*.kt ${KOTLINPATH}/

echo "3. generate .so"

cargo build --target aarch64-linux-android --release
cargo build --target armv7-linux-androideabi --release
cargo build --target x86_64-linux-android --release
cargo build --target x86_64-apple-darwin  --release
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-unknown-linux-gnu-gcc cargo build --target x86_64-unknown-linux-gnu --release

# Copy to Gradle module
mkdir -p ${JNILIBSPATH}/arm64-v8a
mkdir -p ${JNILIBSPATH}/armeabi-v7a
mkdir -p ${JNILIBSPATH}/x86_64
cp ${TARGETPATH}/aarch64-linux-android/release/libuniffi_dtproto.so ${JNILIBSPATH}/arm64-v8a/
cp ${TARGETPATH}/armv7-linux-androideabi/release/libuniffi_dtproto.so ${JNILIBSPATH}/armeabi-v7a/
cp ${TARGETPATH}/x86_64-linux-android/release/libuniffi_dtproto.so ${JNILIBSPATH}/x86_64/

echo "done"
