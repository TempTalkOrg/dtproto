#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")/.."

VERSION=$(sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' package.json | head -1)
DESKTOP_DIR="Desktop"

TARGETS=(
    "aarch64-apple-darwin"
    "x86_64-apple-darwin"
    "x86_64-unknown-linux-gnu"
    "aarch64-unknown-linux-gnu"
    "x86_64-pc-windows-gnu"
)

platform_dir() {
    case "$1" in
        aarch64-apple-darwin)      echo "darwin-arm64" ;;
        x86_64-apple-darwin)       echo "darwin-x64" ;;
        x86_64-unknown-linux-gnu)  echo "linux-x64" ;;
        aarch64-unknown-linux-gnu) echo "linux-arm64" ;;
        x86_64-pc-windows-gnu)     echo "win32-x64" ;;
    esac
}

cdylib_name() {
    case "$1" in
        *-apple-darwin)  echo "libuniffi_dtproto.dylib" ;;
        *-linux-*)       echo "libuniffi_dtproto.so" ;;
        *-windows-*)     echo "uniffi_dtproto.dll" ;;
    esac
}

# --- prerequisites check ---
command -v cargo >/dev/null   || { echo "ERROR: cargo not found"; exit 1; }
command -v zig >/dev/null     || { echo "ERROR: zig not found. Install: brew install zig"; exit 1; }
command -v cargo-zigbuild >/dev/null || { echo "ERROR: cargo-zigbuild not found. Install: cargo install cargo-zigbuild"; exit 1; }

for t in "${TARGETS[@]}"; do
    rustup target list --installed | grep -q "^${t}$" || {
        echo "ERROR: Rust target ${t} not installed. Run: rustup target add ${t}"
        exit 1
    }
done

echo "=== Building dtproto_ffi v${VERSION} for Desktop ==="

echo ""
echo "--- Cleaning build cache ---"
cargo clean

for target in "${TARGETS[@]}"; do
    dir=$(platform_dir "$target")
    lib=$(cdylib_name "$target")

    echo ""
    echo "--- ${dir} (${target}) ---"

    if [[ "$target" == *-apple-* ]]; then
        cargo build --release --target="$target"
    else
        cargo zigbuild --release --target="$target"
    fi

    mkdir -p "${DESKTOP_DIR}/${dir}"
    cp "target/${target}/release/${lib}" "${DESKTOP_DIR}/${dir}/index.node"
    echo "-> ${DESKTOP_DIR}/${dir}/index.node"
done

echo ""
echo "=== Build complete ==="
ls -lh ${DESKTOP_DIR}/*/index.node
