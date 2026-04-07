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

# Detect NDK host tag (darwin-x86_64 / linux-x86_64) and generate .cargo/config.toml
case "$(uname -s)" in
    Darwin) NDK_HOST_TAG="darwin-x86_64" ;;
    Linux)  NDK_HOST_TAG="linux-x86_64" ;;
    *) echo "Unsupported host OS: $(uname -s)"; exit 1 ;;
esac

if [ -z "${ANDROID_NDK_HOME}" ]; then
    echo "ANDROID_NDK_HOME is not set"; exit 1
fi

echo "0. generate .cargo/config.toml for host tag ${NDK_HOST_TAG}"
mkdir -p "${PROJECTPATH}/.cargo"
NDK_BIN="${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/${NDK_HOST_TAG}/bin"
cat > "${PROJECTPATH}/.cargo/config.toml" <<EOF
[target.aarch64-linux-android]
ar = "${NDK_BIN}/llvm-ar"
linker = "${NDK_BIN}/aarch64-linux-android26-clang"

[target.x86_64-linux-android]
ar = "${NDK_BIN}/llvm-ar"
linker = "${NDK_BIN}/x86_64-linux-android26-clang"

[target.armv7-linux-androideabi]
ar = "${NDK_BIN}/llvm-ar"
linker = "${NDK_BIN}/armv7a-linux-androideabi21-clang"
EOF

echo "1. setup."
rustup target add aarch64-linux-android
rustup target add armv7-linux-androideabi
rustup target add x86_64-linux-android
# Desktop targets are only built locally; skip on JitPack (Linux CI)
if [ "${JITPACK}" != "true" ]; then
    rustup target add x86_64-apple-darwin
    rustup target add x86_64-unknown-linux-gnu
fi

echo "2. generate kotlin."

cargo run --bin uniffi-bindgen generate ${SRCPATH}/dtproto.udl --language kotlin

mkdir -p ${KOTLINPATH}
cp ${SRCPATH}/uniffi/dtproto/*.kt ${KOTLINPATH}/

echo "3. generate .so"

cargo build --target aarch64-linux-android --release
cargo build --target armv7-linux-androideabi --release
cargo build --target x86_64-linux-android --release
if [ "${JITPACK}" != "true" ]; then
    cargo build --target x86_64-apple-darwin  --release
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-unknown-linux-gnu-gcc cargo build --target x86_64-unknown-linux-gnu --release
fi

# Copy to Gradle module
mkdir -p ${JNILIBSPATH}/arm64-v8a
mkdir -p ${JNILIBSPATH}/armeabi-v7a
mkdir -p ${JNILIBSPATH}/x86_64
cp ${TARGETPATH}/aarch64-linux-android/release/libuniffi_dtproto.so ${JNILIBSPATH}/arm64-v8a/
cp ${TARGETPATH}/armv7-linux-androideabi/release/libuniffi_dtproto.so ${JNILIBSPATH}/armeabi-v7a/
cp ${TARGETPATH}/x86_64-linux-android/release/libuniffi_dtproto.so ${JNILIBSPATH}/x86_64/

echo "done"
