# DTProto

End-to-end encryption protocol library for secure messaging.

Built in Rust with cross-platform support for Android (JNI/JNA), iOS (UniFFI/Swift), and Node.js (Neon).

## Features

- X25519 Diffie-Hellman key agreement (with optional HKDF-SHA256 key derivation)
- XEdDSA signatures (compatible with Signal Protocol)
- AES-256-GCM authenticated encryption
- Private chat encryption/decryption with identity verification
- Group chat encryption with per-member key distribution
- RTM (Real-Time Messaging) encryption with signature verification
- Key generation, encryption, and distribution

## Building

### Prerequisites

- Rust toolchain (stable)
- For Android: Android NDK
- For iOS: Xcode with iOS targets

### Build

```bash
cargo build --release
```

### Test

```bash
cargo test
```

### Android (.so + Kotlin bindings)

```bash
cd Android
./android-dtproto-jniLibs.sh
```

### iOS (.a + Swift bindings)

```bash
cd scripts
./ios-dtproto-binary.sh
```

## Android Integration (JitPack)

Add JitPack to your project's `settings.gradle.kts`:

```kotlin
dependencyResolutionManagement {
    repositories {
        maven("https://jitpack.io")
    }
}
```

Add the dependency in `build.gradle.kts`:

```kotlin
dependencies {
    implementation("com.github.TempTalkOrg:dtproto:<version>")
}
```

## License

This project is licensed under the [GNU Affero General Public License v3.0](LICENSE).

Portions of the cryptographic code are derived from [libsignal](https://github.com/signalapp/libsignal), licensed under AGPL-3.0.
