// DTProtoTests.swift
//
// XCTest 单元测试 — 集成到 iOS 工程后运行
// 覆盖: 私聊加解密、群聊加解密、身份验证、密钥管理、RTM、group_crypto 全流程 + 错误路径 + 跨平台向量
//
// 使用方式: 将此文件添加到 Xcode test target，确保 DTProto 模块已链接

import XCTest
@testable import DTProto

// MARK: - Helpers

private func hex(_ bytes: [UInt8]) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
}

private func hexToBytes(_ hex: String) -> [UInt8] {
    var bytes = [UInt8]()
    var index = hex.startIndex
    while index < hex.endIndex {
        let nextIndex = hex.index(index, offsetBy: 2)
        let byteString = hex[index..<nextIndex]
        bytes.append(UInt8(byteString, radix: 16)!)
        index = nextIndex
    }
    return bytes
}

// Fixed key pairs (from curve25519.rs test vectors)
private let alicePriKey = hexToBytes("c806439dc9d2c476ffed8f2580c0888d58ab406bf7ae3698879021b96bb4bf59")
private let alicePubKey = hexToBytes("1bb75966f2e93a3691dfff942bb2a466a1c08b8d78ca3f4d6df8b8bfa2e4ee28")
private let bobPriKey   = hexToBytes("b03b34c33a1c44f225b662d2bf4859b8135411fa7b0386d45fb75dc5b91b4466")
private let bobPubKey   = hexToBytes("653614993d2b15ee9e5fd3d86ce719ef4ec1daae1886a87b3f5fa9565a27a22f")
private let carolPriKey = hexToBytes("c097248412e58bf05df487968205132794178e367637f5818f81e0e6ce73e865")
private let carolPubKey = hexToBytes("ab7e717d4a163b7d9a1d8071dfe9dcf8cdcd1cea3339b6356be84d887e322c64")

// MARK: - Private Chat Tests

class DTProtoPrivateChatTests: XCTestCase {

    func testEncryptDecrypt() throws {
        let proto = DtProto(version: 3)
        let encrypted = try proto.encryptMessage(
            pubIdKey: alicePubKey, pubIdKeys: [:],
            localPriKey: bobPriKey, plainText: Array("hello private".utf8))

        let decrypted = try proto.decryptMessage(
            signedEKey: encrypted.signedEKey, theirIdKey: encrypted.identityKey,
            localTheirIdKey: encrypted.identityKey, cachedTheirIdKey: encrypted.identityKey,
            eKey: encrypted.eKey, localPriKey: alicePriKey, ermKey: [], cipherText: encrypted.cipherText)

        XCTAssertEqual(String(bytes: decrypted.plainText, encoding: .utf8), "hello private")
        XCTAssertEqual(decrypted.identityVerifyResult, .match)
    }

    func testIdentityVerifyCacheOutdated() throws {
        let proto = DtProto(version: 3)
        let encrypted = try proto.encryptMessage(
            pubIdKey: alicePubKey, pubIdKeys: [:],
            localPriKey: bobPriKey, plainText: Array("test".utf8))

        // msg == server, msg != cache(carol) → CacheOutdated
        let decrypted = try proto.decryptMessage(
            signedEKey: encrypted.signedEKey, theirIdKey: encrypted.identityKey,
            localTheirIdKey: encrypted.identityKey, cachedTheirIdKey: carolPubKey,
            eKey: encrypted.eKey, localPriKey: alicePriKey, ermKey: [], cipherText: encrypted.cipherText)

        XCTAssertEqual(decrypted.identityVerifyResult, .cacheOutdated)
    }

    func testIdentityVerifySenderKeyUpdated() throws {
        let proto = DtProto(version: 3)
        let encrypted = try proto.encryptMessage(
            pubIdKey: alicePubKey, pubIdKeys: [:],
            localPriKey: bobPriKey, plainText: Array("test".utf8))

        // msg != server(carol), msg == cache → SenderKeyUpdated
        let decrypted = try proto.decryptMessage(
            signedEKey: encrypted.signedEKey, theirIdKey: encrypted.identityKey,
            localTheirIdKey: carolPubKey, cachedTheirIdKey: encrypted.identityKey,
            eKey: encrypted.eKey, localPriKey: alicePriKey, ermKey: [], cipherText: encrypted.cipherText)

        XCTAssertEqual(decrypted.identityVerifyResult, .senderKeyUpdated)
    }

    func testIdentityVerifyAllMismatch() throws {
        let proto = DtProto(version: 3)
        let encrypted = try proto.encryptMessage(
            pubIdKey: alicePubKey, pubIdKeys: [:],
            localPriKey: bobPriKey, plainText: Array("test".utf8))

        // msg != server(alice), msg != cache(carol) → AllMismatch
        let decrypted = try proto.decryptMessage(
            signedEKey: encrypted.signedEKey, theirIdKey: encrypted.identityKey,
            localTheirIdKey: alicePubKey, cachedTheirIdKey: carolPubKey,
            eKey: encrypted.eKey, localPriKey: alicePriKey, ermKey: [], cipherText: encrypted.cipherText)

        XCTAssertEqual(decrypted.identityVerifyResult, .allMismatch)
    }

    func testSignatureVerificationFailure() throws {
        let proto = DtProto(version: 3)
        let encrypted = try proto.encryptMessage(
            pubIdKey: alicePubKey, pubIdKeys: [:],
            localPriKey: bobPriKey, plainText: Array("test".utf8))

        var tampered = encrypted.signedEKey
        tampered[0] ^= 0xFF

        XCTAssertThrowsError(try proto.decryptMessage(
            signedEKey: tampered, theirIdKey: encrypted.identityKey,
            localTheirIdKey: encrypted.identityKey, cachedTheirIdKey: nil,
            eKey: encrypted.eKey, localPriKey: alicePriKey, ermKey: [], cipherText: encrypted.cipherText)
        ) { error in
            guard case DtProtoError.VerifySignatureError = error else {
                return XCTFail("Expected VerifySignatureError, got \(error)")
            }
        }
    }

    func testVersionError() {
        let proto = DtProto(version: 0)
        XCTAssertThrowsError(try proto.encryptMessage(
            pubIdKey: [UInt8](repeating: 0, count: 32), pubIdKeys: [:],
            localPriKey: [UInt8](repeating: 0, count: 32), plainText: [1])
        ) { error in
            guard case DtProtoError.VersionError = error else {
                return XCTFail("Expected VersionError, got \(error)")
            }
        }
    }

    func testV1BackwardCompatible() throws {
        let proto = DtProto(version: 1)
        let encrypted = try proto.encryptMessage(
            pubIdKey: alicePubKey, pubIdKeys: [:],
            localPriKey: bobPriKey, plainText: Array("v1 msg".utf8))

        let decrypted = try proto.decryptMessage(
            signedEKey: encrypted.signedEKey, theirIdKey: encrypted.identityKey,
            localTheirIdKey: encrypted.identityKey, cachedTheirIdKey: nil,
            eKey: encrypted.eKey, localPriKey: alicePriKey, ermKey: [], cipherText: encrypted.cipherText)

        XCTAssertEqual(String(bytes: decrypted.plainText, encoding: .utf8), "v1 msg")
    }

    func testV2BackwardCompatible() throws {
        let proto = DtProto(version: 2)
        let encrypted = try proto.encryptMessage(
            pubIdKey: alicePubKey, pubIdKeys: [:],
            localPriKey: bobPriKey, plainText: Array("v2 msg".utf8))

        let decrypted = try proto.decryptMessage(
            signedEKey: encrypted.signedEKey, theirIdKey: encrypted.identityKey,
            localTheirIdKey: encrypted.identityKey, cachedTheirIdKey: nil,
            eKey: encrypted.eKey, localPriKey: alicePriKey, ermKey: [], cipherText: encrypted.cipherText)

        XCTAssertEqual(String(bytes: decrypted.plainText, encoding: .utf8), "v2 msg")
    }
}

// MARK: - Group Chat Tests

class DTProtoGroupChatTests: XCTestCase {

    func testGroupEncryptDecrypt() throws {
        let proto = DtProto(version: 3)
        let pubIdKeys: [String: [UInt8]] = ["alice": alicePubKey, "carol": carolPubKey]
        let encrypted = try proto.encryptMessage(
            pubIdKey: [], pubIdKeys: pubIdKeys,
            localPriKey: bobPriKey, plainText: Array("hello group".utf8))

        XCTAssertNotNil(encrypted.ermKeys)

        let decrypted = try proto.decryptMessage(
            signedEKey: encrypted.signedEKey, theirIdKey: encrypted.identityKey,
            localTheirIdKey: encrypted.identityKey, cachedTheirIdKey: nil,
            eKey: encrypted.eKey, localPriKey: alicePriKey,
            ermKey: encrypted.ermKeys!["alice"]!, cipherText: encrypted.cipherText)

        XCTAssertEqual(String(bytes: decrypted.plainText, encoding: .utf8), "hello group")
        XCTAssertEqual(decrypted.identityVerifyResult, .match)
    }
}

// MARK: - Key Management Tests

class DTProtoKeyTests: XCTestCase {

    func testEncryptDecryptKey() throws {
        let proto = DtProto(version: 3)
        let pubIdKeys: [String: [UInt8]] = ["alice": alicePubKey]
        let encryptedKey = try proto.encryptKey(pubIdKeys: pubIdKeys, mKey: nil)

        XCTAssertEqual(encryptedKey.mKey.count, 64)
        XCTAssertTrue(encryptedKey.eMKeys["alice"]!.count > 0)

        let decryptedKey = try proto.decryptKey(
            eKey: encryptedKey.eKey, localPriKey: alicePriKey, eMKey: encryptedKey.eMKeys["alice"]!)
        XCTAssertEqual(hex(decryptedKey.mKey), hex(encryptedKey.mKey))
    }

    func testEncryptKeyWithExistingMKey() throws {
        let proto = DtProto(version: 3)
        let existingMKey = proto.generateKey()
        let pubIdKeys: [String: [UInt8]] = ["alice": alicePubKey]

        let encryptedKey = try proto.encryptKey(pubIdKeys: pubIdKeys, mKey: existingMKey)
        XCTAssertEqual(hex(encryptedKey.mKey), hex(existingMKey))

        let decryptedKey = try proto.decryptKey(
            eKey: encryptedKey.eKey, localPriKey: alicePriKey, eMKey: encryptedKey.eMKeys["alice"]!)
        XCTAssertEqual(hex(decryptedKey.mKey), hex(existingMKey))
    }

    func testGenerateKey() {
        let proto = DtProto(version: 3)
        let key1 = proto.generateKey()
        let key2 = proto.generateKey()

        XCTAssertEqual(key1.count, 64)
        XCTAssertNotEqual(hex(key1), hex(key2))
    }
}

// MARK: - RTM Tests

class DTProtoRTMTests: XCTestCase {

    func testRTMEncryptDecrypt() throws {
        let proto = DtProto(version: 3)
        let aesKey = Array(proto.generateKey().prefix(32))
        let plainText = Array("hello rtm".utf8)

        let encrypted = try proto.encryptRtmMessage(aesKey: aesKey, localPriKey: alicePriKey, plainText: plainText)
        XCTAssertEqual(encrypted.signature.count, 64)

        let decrypted = try proto.decryptRtmMessage(
            signature: encrypted.signature, theirLocalIdKey: alicePubKey,
            aesKey: aesKey, cipherText: encrypted.cipherText)

        XCTAssertEqual(String(bytes: decrypted.plainText, encoding: .utf8), "hello rtm")
        XCTAssertTrue(decrypted.verifiedIdResult)
    }

    func testRTMDecryptWithoutIdKey() throws {
        let proto = DtProto(version: 3)
        let aesKey = Array(proto.generateKey().prefix(32))
        let plainText = Array("hello rtm no verify".utf8)

        let encrypted = try proto.encryptRtmMessage(aesKey: aesKey, localPriKey: alicePriKey, plainText: plainText)

        let decrypted = try proto.decryptRtmMessage(
            signature: encrypted.signature, theirLocalIdKey: nil,
            aesKey: aesKey, cipherText: encrypted.cipherText)

        XCTAssertEqual(String(bytes: decrypted.plainText, encoding: .utf8), "hello rtm no verify")
        XCTAssertFalse(decrypted.verifiedIdResult)
    }
}

// MARK: - Group Crypto Tests

class DTGroupCryptoTests: XCTestCase {

    private func gc() -> DtGroupCrypto { DtGroupCrypto(version: 1) }

    // --- derive_keys ---

    func testDeriveKeysDeterministic() throws {
        let rGroup = [UInt8](repeating: 0x42, count: 32)
        let keys1 = try gc().deriveKeys(rGroup: rGroup)
        let keys2 = try gc().deriveKeys(rGroup: rGroup)

        XCTAssertEqual(keys1.kGroup.count, 32)
        XCTAssertEqual(keys1.skBind.count, 32)
        XCTAssertEqual(keys1.pkBind.count, 32)
        XCTAssertEqual(keys1.kGroup, keys2.kGroup)
        XCTAssertEqual(keys1.skBind, keys2.skBind)
        XCTAssertEqual(keys1.pkBind, keys2.pkBind)
    }

    func testDeriveKeysInvalidLength() {
        XCTAssertThrowsError(try gc().deriveKeys(rGroup: [UInt8](repeating: 0, count: 16))) { error in
            guard case DtProtoError.InvalidRGroupLength = error else {
                return XCTFail("Expected InvalidRGroupLength, got \(error)")
            }
        }
    }

    // --- encrypt / decrypt ---

    func testEncryptDecryptRoundtrip() throws {
        let keys = try gc().deriveKeys(rGroup: [UInt8](repeating: 0xAB, count: 32))
        let aad = Array("tt-grp-v1|gcm|name".utf8)
        let plaintext = Array("test group name".utf8)

        let blob = try gc().encrypt(kGroup: keys.kGroup, plaintext: plaintext, aad: aad)
        XCTAssertEqual(blob[0], 0x01, "blob version")
        XCTAssertTrue(blob.count >= 29) // 1 + 12 + 16 overhead

        let decrypted = try gc().decrypt(kGroup: keys.kGroup, blob: blob, aad: aad)
        XCTAssertEqual(String(bytes: decrypted, encoding: .utf8), "test group name")
    }

    func testDecryptWrongKey() throws {
        let keys = try gc().deriveKeys(rGroup: [UInt8](repeating: 0xAB, count: 32))
        let wrongKey = [UInt8](repeating: 0xCD, count: 32)
        let aad = Array("tt-grp-v1|gcm|name".utf8)

        let blob = try gc().encrypt(kGroup: keys.kGroup, plaintext: Array("test".utf8), aad: aad)
        XCTAssertThrowsError(try gc().decrypt(kGroup: wrongKey, blob: blob, aad: aad)) { error in
            guard case DtProtoError.GroupDecryptError = error else {
                return XCTFail("Expected GroupDecryptError, got \(error)")
            }
        }
    }

    func testDecryptWrongAad() throws {
        let keys = try gc().deriveKeys(rGroup: [UInt8](repeating: 0xAB, count: 32))
        let aad = Array("tt-grp-v1|gcm|name".utf8)
        let wrongAad = Array("tt-grp-v1|gcm|avatar".utf8)

        let blob = try gc().encrypt(kGroup: keys.kGroup, plaintext: Array("test".utf8), aad: aad)
        XCTAssertThrowsError(try gc().decrypt(kGroup: keys.kGroup, blob: blob, aad: wrongAad)) { error in
            guard case DtProtoError.GroupDecryptError = error else {
                return XCTFail("Expected GroupDecryptError, got \(error)")
            }
        }
    }

    func testEncryptEmptyPlaintext() throws {
        let keys = try gc().deriveKeys(rGroup: [UInt8](repeating: 0xAB, count: 32))
        XCTAssertThrowsError(try gc().encrypt(kGroup: keys.kGroup, plaintext: [], aad: Array("aad".utf8))) { error in
            guard case DtProtoError.ParamsError = error else {
                return XCTFail("Expected ParamsError, got \(error)")
            }
        }
    }

    func testEncryptEmptyAad() throws {
        let keys = try gc().deriveKeys(rGroup: [UInt8](repeating: 0xAB, count: 32))
        XCTAssertThrowsError(try gc().encrypt(kGroup: keys.kGroup, plaintext: Array("test".utf8), aad: [])) { error in
            guard case DtProtoError.ParamsError = error else {
                return XCTFail("Expected ParamsError, got \(error)")
            }
        }
    }

    func testDecryptEmptyAad() throws {
        let keys = try gc().deriveKeys(rGroup: [UInt8](repeating: 0xAB, count: 32))
        XCTAssertThrowsError(try gc().decrypt(kGroup: keys.kGroup, blob: [UInt8](repeating: 0x01, count: 30), aad: [])) { error in
            guard case DtProtoError.ParamsError = error else {
                return XCTFail("Expected ParamsError, got \(error)")
            }
        }
    }

    func testInvalidKGroupLength() {
        XCTAssertThrowsError(try gc().encrypt(kGroup: [UInt8](repeating: 0, count: 16), plaintext: Array("test".utf8), aad: Array("aad".utf8))) { error in
            guard case DtProtoError.InvalidKGroupLength = error else {
                return XCTFail("Expected InvalidKGroupLength, got \(error)")
            }
        }
    }

    func testDecryptBlobTooShort() throws {
        let keys = try gc().deriveKeys(rGroup: [UInt8](repeating: 0xAB, count: 32))
        XCTAssertThrowsError(try gc().decrypt(kGroup: keys.kGroup, blob: [UInt8](repeating: 0x01, count: 10), aad: Array("aad".utf8))) { error in
            guard case DtProtoError.BlobTooShort = error else {
                return XCTFail("Expected BlobTooShort, got \(error)")
            }
        }
    }

    func testEncryptUnsupportedVersion() throws {
        let keys = try DtGroupCrypto(version: 1).deriveKeys(rGroup: [UInt8](repeating: 0xAB, count: 32))
        XCTAssertThrowsError(try DtGroupCrypto(version: 0).encrypt(kGroup: keys.kGroup, plaintext: Array("test".utf8), aad: Array("aad".utf8))) { error in
            guard case DtProtoError.UnsupportedBlobVersion = error else {
                return XCTFail("Expected UnsupportedBlobVersion, got \(error)")
            }
        }
    }

    // --- sign / verify uid ---

    func testSignVerifyUid() throws {
        let keys = try gc().deriveKeys(rGroup: [UInt8](repeating: 0xAB, count: 32))
        let signature = try gc().signUid(skBind: keys.skBind, uid: "user123")
        XCTAssertEqual(signature.count, 64)

        let valid = try gc().verifyUid(pkBind: keys.pkBind, uid: "user123", signature: signature)
        XCTAssertTrue(valid)
    }

    func testVerifyUidWrongPk() throws {
        let keys = try gc().deriveKeys(rGroup: [UInt8](repeating: 0xAB, count: 32))
        let wrongKeys = try gc().deriveKeys(rGroup: [UInt8](repeating: 0xCD, count: 32))

        let signature = try gc().signUid(skBind: keys.skBind, uid: "user123")
        let valid = try gc().verifyUid(pkBind: wrongKeys.pkBind, uid: "user123", signature: signature)
        XCTAssertFalse(valid)
    }

    func testVerifyUidWrongUid() throws {
        let keys = try gc().deriveKeys(rGroup: [UInt8](repeating: 0xAB, count: 32))
        let signature = try gc().signUid(skBind: keys.skBind, uid: "user123")
        let valid = try gc().verifyUid(pkBind: keys.pkBind, uid: "hacker456", signature: signature)
        XCTAssertFalse(valid)
    }

    func testVerifyUidTamperedSignature() throws {
        let keys = try gc().deriveKeys(rGroup: [UInt8](repeating: 0xAB, count: 32))
        var signature = try gc().signUid(skBind: keys.skBind, uid: "user123")
        signature[0] ^= 0xFF
        let valid = try gc().verifyUid(pkBind: keys.pkBind, uid: "user123", signature: signature)
        XCTAssertFalse(valid)
    }

    func testSignUidEmpty() throws {
        let keys = try gc().deriveKeys(rGroup: [UInt8](repeating: 0xAB, count: 32))
        XCTAssertThrowsError(try gc().signUid(skBind: keys.skBind, uid: "")) { error in
            guard case DtProtoError.ParamsError = error else {
                return XCTFail("Expected ParamsError, got \(error)")
            }
        }
    }

    func testVerifyUidEmpty() throws {
        let keys = try gc().deriveKeys(rGroup: [UInt8](repeating: 0xAB, count: 32))
        XCTAssertThrowsError(try gc().verifyUid(pkBind: keys.pkBind, uid: "", signature: [UInt8](repeating: 0, count: 64))) { error in
            guard case DtProtoError.ParamsError = error else {
                return XCTFail("Expected ParamsError, got \(error)")
            }
        }
    }

    func testInvalidSkBindLength() {
        XCTAssertThrowsError(try gc().signUid(skBind: [UInt8](repeating: 0, count: 16), uid: "user123")) { error in
            guard case DtProtoError.InvalidSkBindLength = error else {
                return XCTFail("Expected InvalidSkBindLength, got \(error)")
            }
        }
    }

    func testInvalidPkBindLength() {
        XCTAssertThrowsError(try gc().verifyUid(pkBind: [UInt8](repeating: 0, count: 16), uid: "user123", signature: [UInt8](repeating: 0, count: 64))) { error in
            guard case DtProtoError.InvalidPkBindLength = error else {
                return XCTFail("Expected InvalidPkBindLength, got \(error)")
            }
        }
    }

    func testInvalidSignatureLength() throws {
        let keys = try gc().deriveKeys(rGroup: [UInt8](repeating: 0xAB, count: 32))
        XCTAssertThrowsError(try gc().verifyUid(pkBind: keys.pkBind, uid: "user123", signature: [UInt8](repeating: 0, count: 32))) { error in
            guard case DtProtoError.InvalidSignatureLength = error else {
                return XCTFail("Expected InvalidSignatureLength, got \(error)")
            }
        }
    }

    // --- cross-platform vector ---

    func testCrossPlatformVector() throws {
        // R_group = [0x00, 0x01, ..., 0x1f]
        let rGroup = (0..<32).map { UInt8($0) }
        let keys = try gc().deriveKeys(rGroup: rGroup)

        XCTAssertEqual(hex(keys.kGroup),
            "c429ae7559b8f8a480f68e54e0becb5ef22d142e137ab10f4dd535e3a3f777ef")
        XCTAssertEqual(hex(keys.skBind),
            "aefb15f01c6e8c5bd3b03a9122a97b8198d69ce6138d833983f4ee46394e786b")
        XCTAssertEqual(hex(keys.pkBind),
            "1c37ad97463331dbcfdc44a0697482fdc00e33a6462c362980c1834f5ce16d3d")

        let signature = try gc().signUid(skBind: keys.skBind, uid: "test-uid-001")
        XCTAssertEqual(hex(signature),
            "3e6d31fed3bf0bba4d06b4eb10e2de6bb419030b973bf49fd3666ff818cda4c5a42b109a431143a7e2200fb1023b9f6627303ed8ea9391de04cc056201eb8404")

        let valid = try gc().verifyUid(pkBind: keys.pkBind, uid: "test-uid-001", signature: signature)
        XCTAssertTrue(valid)
    }
}
