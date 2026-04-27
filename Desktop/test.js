const dtproto = require('..');

var emptyArray = new Uint8Array()

// identity_verify_result: 0=Match, 1=CacheOutdated, 2=SenderKeyUpdated, 3=AllMismatch

function assert(condition, msg) {
    if (!condition) throw new Error("ASSERT FAILED: " + msg);
}

function assertEq(a, b, msg) {
    assert(a === b, msg + " expected " + b + " got " + a);
}

function buf2hex(buffer) {
    return [...new Uint8Array(buffer)]
        .map(x => x.toString(16).padStart(2, '0'))
        .join('');
}

function hex2buf(hex) {
    var typedArray = new Uint8Array(hex.match(/[\da-f]{2}/gi).map(function (h) {
        return parseInt(h, 16)
    }))
    return typedArray.buffer
}

let passed = 0;
let failed = 0;

function runTest(name, fn) {
    try {
        fn();
        console.log("PASSED: " + name);
        passed++;
    } catch(error) {
        console.log("FAILED: " + name + " - " + error.message);
        failed++;
    }
}

// Fixed key pairs (valid X25519 key pairs for testing)
// Alice (from curve25519.rs test_agreement)
var alice_pri_key = hex2buf("c806439dc9d2c476ffed8f2580c0888d58ab406bf7ae3698879021b96bb4bf59");
var alice_pub_key = hex2buf("1bb75966f2e93a3691dfff942bb2a466a1c08b8d78ca3f4d6df8b8bfa2e4ee28");

// Bob (from curve25519.rs test_agreement)
var bob_pri_key = hex2buf("b03b34c33a1c44f225b662d2bf4859b8135411fa7b0386d45fb75dc5b91b4466");
var bob_pub_key = hex2buf("653614993d2b15ee9e5fd3d86ce719ef4ec1daae1886a87b3f5fa9565a27a22f");

// Carol (from curve25519.rs test_signature alice_identity)
var carol_pri_key = hex2buf("c097248412e58bf05df487968205132794178e367637f5818f81e0e6ce73e865");
var carol_pub_key = hex2buf("ab7e717d4a163b7d9a1d8071dfe9dcf8cdcd1cea3339b6356be84d887e322c64");

// ==================== test: private chat encrypt/decrypt ====================
runTest("private_chat_encrypt_decrypt", () => {
    let encrypted = dtproto.encrypt_message(3.0, alice_pub_key, {}, bob_pri_key, new TextEncoder().encode("hello private").buffer);

    let decrypted = dtproto.decrypt_message(3.0,
        encrypted.signed_e_key, encrypted.identity_key, encrypted.identity_key,
        encrypted.identity_key, // cached == msg == server
        encrypted.e_key, alice_pri_key, emptyArray.buffer, encrypted.cipher_text);

    assertEq(new TextDecoder().decode(decrypted.plain_text), "hello private", "plaintext");
    assertEq(decrypted.identity_verify_result, 0, "identity Match");
});

// ==================== test: group chat encrypt/decrypt ====================
runTest("group_chat_encrypt_decrypt", () => {
    let pub_id_keys = {"alice": alice_pub_key, "carol": carol_pub_key};
    let encrypted = dtproto.encrypt_message(3.0, emptyArray.buffer, pub_id_keys, bob_pri_key, new TextEncoder().encode("hello group").buffer);

    assert(encrypted.erm_keys !== undefined, "erm_keys should exist");

    let decrypted = dtproto.decrypt_message(3.0,
        encrypted.signed_e_key, encrypted.identity_key, encrypted.identity_key,
        emptyArray.buffer, // no cache
        encrypted.e_key, alice_pri_key, encrypted.erm_keys["alice"], encrypted.cipher_text);

    assertEq(new TextDecoder().decode(decrypted.plain_text), "hello group", "plaintext");
    assertEq(decrypted.identity_verify_result, 0, "identity Match");
});

// ==================== test: identity verify - CacheOutdated ====================
runTest("identity_verify_cache_outdated", () => {
    let encrypted = dtproto.encrypt_message(3.0, alice_pub_key, {}, bob_pri_key, new TextEncoder().encode("test").buffer);

    // msg == server, msg != cache(carol) → CacheOutdated
    let decrypted = dtproto.decrypt_message(3.0,
        encrypted.signed_e_key, encrypted.identity_key, encrypted.identity_key,
        carol_pub_key, // cache is different
        encrypted.e_key, alice_pri_key, emptyArray.buffer, encrypted.cipher_text);

    assertEq(decrypted.identity_verify_result, 1, "CacheOutdated");
});

// ==================== test: identity verify - SenderKeyUpdated ====================
runTest("identity_verify_sender_key_updated", () => {
    let encrypted = dtproto.encrypt_message(3.0, alice_pub_key, {}, bob_pri_key, new TextEncoder().encode("test").buffer);

    // msg != server(carol), msg == cache(bob_pub) → SenderKeyUpdated
    let decrypted = dtproto.decrypt_message(3.0,
        encrypted.signed_e_key, encrypted.identity_key, carol_pub_key,
        encrypted.identity_key, // cache matches msg
        encrypted.e_key, alice_pri_key, emptyArray.buffer, encrypted.cipher_text);

    assertEq(decrypted.identity_verify_result, 2, "SenderKeyUpdated");
});

// ==================== test: identity verify - AllMismatch ====================
runTest("identity_verify_all_mismatch", () => {
    let encrypted = dtproto.encrypt_message(3.0, alice_pub_key, {}, bob_pri_key, new TextEncoder().encode("test").buffer);

    // msg != server(alice), msg != cache(carol) → AllMismatch
    let decrypted = dtproto.decrypt_message(3.0,
        encrypted.signed_e_key, encrypted.identity_key, alice_pub_key,
        carol_pub_key,
        encrypted.e_key, alice_pri_key, emptyArray.buffer, encrypted.cipher_text);

    assertEq(decrypted.identity_verify_result, 3, "AllMismatch");
});

// ==================== test: signature verification failure ====================
runTest("signature_verification_failure", () => {
    let encrypted = dtproto.encrypt_message(3.0, alice_pub_key, {}, bob_pri_key, new TextEncoder().encode("test").buffer);

    // Tamper with signed_e_key to cause signature failure
    let tampered_sig = new ArrayBuffer(encrypted.signed_e_key.byteLength);
    new Uint8Array(tampered_sig).set(new Uint8Array(encrypted.signed_e_key));
    new Uint8Array(tampered_sig)[0] ^= 0xFF;

    try {
        dtproto.decrypt_message(3.0,
            tampered_sig, encrypted.identity_key, encrypted.identity_key,
            emptyArray.buffer,
            encrypted.e_key, alice_pri_key, emptyArray.buffer, encrypted.cipher_text);
        throw new Error("should have thrown");
    } catch(error) {
        assertEq(error.code, 3, "VerifySignatureError");
    }
});

// ==================== test: encrypt/decrypt key ====================
runTest("encrypt_decrypt_key", () => {
    let pub_id_keys = {"alice": alice_pub_key};
    let encrypted_key = dtproto.encrypt_key(3.0, pub_id_keys, emptyArray.buffer);

    assertEq(encrypted_key.m_key.byteLength, 64, "m_key length");
    assert(encrypted_key.e_m_keys["alice"].byteLength > 0, "alice e_m_key exists");

    let decrypted_key = dtproto.decrypt_key(3.0, encrypted_key.e_key, alice_pri_key, encrypted_key.e_m_keys["alice"]);
    assertEq(buf2hex(decrypted_key.m_key), buf2hex(encrypted_key.m_key), "m_key roundtrip");
});

// ==================== test: encrypt key with existing m_key ====================
runTest("encrypt_key_with_existing_m_key", () => {
    let existing_m_key = dtproto.generate_key(3.0);
    let pub_id_keys = {"alice": alice_pub_key};

    let encrypted_key = dtproto.encrypt_key(3.0, pub_id_keys, existing_m_key);
    assertEq(buf2hex(encrypted_key.m_key), buf2hex(existing_m_key), "m_key preserved");

    let decrypted_key = dtproto.decrypt_key(3.0, encrypted_key.e_key, alice_pri_key, encrypted_key.e_m_keys["alice"]);
    assertEq(buf2hex(decrypted_key.m_key), buf2hex(existing_m_key), "m_key decrypt match");
});

// ==================== test: RTM encrypt/decrypt ====================
runTest("rtm_encrypt_decrypt", () => {
    let aes_key = dtproto.generate_key(3.0).slice(0, 32);
    let plain_text = new TextEncoder().encode("hello rtm").buffer;

    let encrypted = dtproto.encrypt_rtm_message(3.0, aes_key, alice_pri_key, plain_text);

    assertEq(encrypted.signature.byteLength, 64, "signature length");

    let decrypted = dtproto.decrypt_rtm_message(3.0, encrypted.signature, alice_pub_key, aes_key, encrypted.cipher_text);
    assertEq(new TextDecoder().decode(decrypted.plain_text), "hello rtm", "plaintext");
    assertEq(decrypted.verified_id_result, true, "signature verified");
});

// ==================== test: RTM decrypt without id key ====================
runTest("rtm_decrypt_without_id_key", () => {
    let aes_key = dtproto.generate_key(3.0).slice(0, 32);
    let plain_text = new TextEncoder().encode("hello rtm no verify").buffer;

    let encrypted = dtproto.encrypt_rtm_message(3.0, aes_key, alice_pri_key, plain_text);

    let decrypted = dtproto.decrypt_rtm_message(3.0, encrypted.signature, emptyArray.buffer, aes_key, encrypted.cipher_text);
    assertEq(new TextDecoder().decode(decrypted.plain_text), "hello rtm no verify", "plaintext");
    assertEq(decrypted.verified_id_result, false, "no id_key so not verified");
});

// ==================== test: generate key ====================
runTest("generate_key", () => {
    let key1 = dtproto.generate_key(3.0);
    let key2 = dtproto.generate_key(3.0);

    assertEq(key1.byteLength, 64, "key length");
    assert(buf2hex(key1) !== buf2hex(key2), "two keys should differ");
});

// ==================== test: version error ====================
runTest("version_error", () => {
    try {
        dtproto.encrypt_message(0, new Uint8Array(32).buffer, {}, new Uint8Array(32).buffer, new Uint8Array([1]).buffer);
        throw new Error("should have thrown");
    } catch(error) {
        assertEq(error.code, 1, "VersionError");
    }
});

// ==================== test: v1 backward compatible ====================
runTest("v1_backward_compatible", () => {
    let encrypted = dtproto.encrypt_message(1.0, alice_pub_key, {}, bob_pri_key, new TextEncoder().encode("v1 msg").buffer);

    let decrypted = dtproto.decrypt_message(1.0,
        encrypted.signed_e_key, encrypted.identity_key, encrypted.identity_key,
        emptyArray.buffer,
        encrypted.e_key, alice_pri_key, emptyArray.buffer, encrypted.cipher_text);

    assertEq(new TextDecoder().decode(decrypted.plain_text), "v1 msg", "plaintext");
});

// ==================== test: v2 backward compatible ====================
runTest("v2_backward_compatible", () => {
    let encrypted = dtproto.encrypt_message(2.0, alice_pub_key, {}, bob_pri_key, new TextEncoder().encode("v2 msg").buffer);

    let decrypted = dtproto.decrypt_message(2.0,
        encrypted.signed_e_key, encrypted.identity_key, encrypted.identity_key,
        emptyArray.buffer,
        encrypted.e_key, alice_pri_key, emptyArray.buffer, encrypted.cipher_text);

    assertEq(new TextDecoder().decode(decrypted.plain_text), "v2 msg", "plaintext");
});

// ==================== test: group_crypto derive_keys deterministic ====================
runTest("group_crypto_derive_keys_deterministic", () => {
    let r_group = new Uint8Array(32).fill(0x42).buffer;
    let keys1 = dtproto.group_crypto_derive_keys(1, r_group);
    let keys2 = dtproto.group_crypto_derive_keys(1, r_group);

    assertEq(keys1.k_group.byteLength, 32, "k_group length");
    assertEq(keys1.sk_bind.byteLength, 32, "sk_bind length");
    assertEq(keys1.pk_bind.byteLength, 32, "pk_bind length");
    assertEq(buf2hex(keys1.k_group), buf2hex(keys2.k_group), "k_group deterministic");
    assertEq(buf2hex(keys1.sk_bind), buf2hex(keys2.sk_bind), "sk_bind deterministic");
    assertEq(buf2hex(keys1.pk_bind), buf2hex(keys2.pk_bind), "pk_bind deterministic");
});

// ==================== test: group_crypto derive_keys invalid length ====================
runTest("group_crypto_derive_keys_invalid_length", () => {
    try {
        dtproto.group_crypto_derive_keys(1, new Uint8Array(16).buffer);
        throw new Error("should have thrown");
    } catch(error) {
        assertEq(error.code, 100, "InvalidRGroupLength");
    }
});

// ==================== test: group_crypto encrypt/decrypt roundtrip ====================
runTest("group_crypto_encrypt_decrypt", () => {
    let r_group = new Uint8Array(32).fill(0xAB).buffer;
    let keys = dtproto.group_crypto_derive_keys(1, r_group);
    let aad = new TextEncoder().encode("tt-grp-v1|gcm|name").buffer;
    let plaintext = new TextEncoder().encode("test group name").buffer;

    let blob = dtproto.group_crypto_encrypt(1, keys.k_group, plaintext, aad);
    assert(blob.byteLength > 0, "blob not empty");
    assert(new Uint8Array(blob)[0] === 0x01, "blob version is 0x01");

    let decrypted = dtproto.group_crypto_decrypt(1, keys.k_group, blob, aad);
    assertEq(new TextDecoder().decode(decrypted), "test group name", "plaintext roundtrip");
});

// ==================== test: group_crypto decrypt wrong key ====================
runTest("group_crypto_decrypt_wrong_key", () => {
    let keys = dtproto.group_crypto_derive_keys(1, new Uint8Array(32).fill(0xAB).buffer);
    let wrong_key = new Uint8Array(32).fill(0xCD).buffer;
    let aad = new TextEncoder().encode("tt-grp-v1|gcm|name").buffer;
    let plaintext = new TextEncoder().encode("test").buffer;

    let blob = dtproto.group_crypto_encrypt(1, keys.k_group, plaintext, aad);
    try {
        dtproto.group_crypto_decrypt(1, wrong_key, blob, aad);
        throw new Error("should have thrown");
    } catch(error) {
        assertEq(error.code, 109, "GroupDecryptError");
    }
});

// ==================== test: group_crypto decrypt wrong aad ====================
runTest("group_crypto_decrypt_wrong_aad", () => {
    let keys = dtproto.group_crypto_derive_keys(1, new Uint8Array(32).fill(0xAB).buffer);
    let aad = new TextEncoder().encode("tt-grp-v1|gcm|name").buffer;
    let wrong_aad = new TextEncoder().encode("tt-grp-v1|gcm|avatar").buffer;
    let plaintext = new TextEncoder().encode("test").buffer;

    let blob = dtproto.group_crypto_encrypt(1, keys.k_group, plaintext, aad);
    try {
        dtproto.group_crypto_decrypt(1, keys.k_group, blob, wrong_aad);
        throw new Error("should have thrown");
    } catch(error) {
        assertEq(error.code, 109, "GroupDecryptError");
    }
});

// ==================== test: group_crypto encrypt empty plaintext ====================
runTest("group_crypto_encrypt_empty_plaintext", () => {
    let keys = dtproto.group_crypto_derive_keys(1, new Uint8Array(32).fill(0xAB).buffer);
    try {
        dtproto.group_crypto_encrypt(1, keys.k_group, new ArrayBuffer(0), new TextEncoder().encode("aad").buffer);
        throw new Error("should have thrown");
    } catch(error) {
        assertEq(error.code, 2, "ParamsError");
    }
});

// ==================== test: group_crypto encrypt empty aad ====================
runTest("group_crypto_encrypt_empty_aad", () => {
    let keys = dtproto.group_crypto_derive_keys(1, new Uint8Array(32).fill(0xAB).buffer);
    try {
        dtproto.group_crypto_encrypt(1, keys.k_group, new TextEncoder().encode("test").buffer, new ArrayBuffer(0));
        throw new Error("should have thrown");
    } catch(error) {
        assertEq(error.code, 2, "ParamsError");
    }
});

// ==================== test: group_crypto invalid k_group length ====================
runTest("group_crypto_invalid_k_group_length", () => {
    try {
        dtproto.group_crypto_encrypt(1, new Uint8Array(16).buffer, new TextEncoder().encode("test").buffer, new TextEncoder().encode("aad").buffer);
        throw new Error("should have thrown");
    } catch(error) {
        assertEq(error.code, 101, "InvalidKGroupLength");
    }
});

// ==================== test: group_crypto decrypt blob too short ====================
runTest("group_crypto_decrypt_blob_too_short", () => {
    let keys = dtproto.group_crypto_derive_keys(1, new Uint8Array(32).fill(0xAB).buffer);
    try {
        dtproto.group_crypto_decrypt(1, keys.k_group, new Uint8Array(10).buffer, new TextEncoder().encode("aad").buffer);
        throw new Error("should have thrown");
    } catch(error) {
        assertEq(error.code, 107, "BlobTooShort");
    }
});

// ==================== test: group_crypto sign/verify uid ====================
runTest("group_crypto_sign_verify_uid", () => {
    let keys = dtproto.group_crypto_derive_keys(1, new Uint8Array(32).fill(0xAB).buffer);

    let signature = dtproto.group_crypto_sign_uid(1, keys.sk_bind, "user123");
    assertEq(signature.byteLength, 64, "signature length");

    let valid = dtproto.group_crypto_verify_uid(1, keys.pk_bind, "user123", signature);
    assertEq(valid, true, "signature valid");
});

// ==================== test: group_crypto verify uid wrong pk ====================
runTest("group_crypto_verify_uid_wrong_pk", () => {
    let keys = dtproto.group_crypto_derive_keys(1, new Uint8Array(32).fill(0xAB).buffer);
    let wrong_keys = dtproto.group_crypto_derive_keys(1, new Uint8Array(32).fill(0xCD).buffer);

    let signature = dtproto.group_crypto_sign_uid(1, keys.sk_bind, "user123");
    let valid = dtproto.group_crypto_verify_uid(1, wrong_keys.pk_bind, "user123", signature);
    assertEq(valid, false, "wrong pk should fail");
});

// ==================== test: group_crypto verify uid wrong uid ====================
runTest("group_crypto_verify_uid_wrong_uid", () => {
    let keys = dtproto.group_crypto_derive_keys(1, new Uint8Array(32).fill(0xAB).buffer);

    let signature = dtproto.group_crypto_sign_uid(1, keys.sk_bind, "user123");
    let valid = dtproto.group_crypto_verify_uid(1, keys.pk_bind, "hacker456", signature);
    assertEq(valid, false, "wrong uid should fail");
});

// ==================== test: group_crypto sign uid empty uid ====================
runTest("group_crypto_sign_uid_empty", () => {
    let keys = dtproto.group_crypto_derive_keys(1, new Uint8Array(32).fill(0xAB).buffer);
    try {
        dtproto.group_crypto_sign_uid(1, keys.sk_bind, "");
        throw new Error("should have thrown");
    } catch(error) {
        assertEq(error.code, 2, "ParamsError");
    }
});

// ==================== test: group_crypto invalid sk_bind length ====================
runTest("group_crypto_invalid_sk_bind_length", () => {
    try {
        dtproto.group_crypto_sign_uid(1, new Uint8Array(16).buffer, "user123");
        throw new Error("should have thrown");
    } catch(error) {
        assertEq(error.code, 102, "InvalidSkBindLength");
    }
});

// ==================== test: group_crypto invalid pk_bind length ====================
runTest("group_crypto_invalid_pk_bind_length", () => {
    try {
        dtproto.group_crypto_verify_uid(1, new Uint8Array(16).buffer, "user123", new Uint8Array(64).buffer);
        throw new Error("should have thrown");
    } catch(error) {
        assertEq(error.code, 103, "InvalidPkBindLength");
    }
});

// ==================== test: group_crypto invalid signature length ====================
runTest("group_crypto_invalid_signature_length", () => {
    let keys = dtproto.group_crypto_derive_keys(1, new Uint8Array(32).fill(0xAB).buffer);
    try {
        dtproto.group_crypto_verify_uid(1, keys.pk_bind, "user123", new Uint8Array(32).buffer);
        throw new Error("should have thrown");
    } catch(error) {
        assertEq(error.code, 105, "InvalidSignatureLength");
    }
});

// ==================== test: group_crypto cross-platform vector ====================
runTest("group_crypto_cross_platform_vector", () => {
    // R_group = [0x00, 0x01, ..., 0x1f]
    let r_group = new Uint8Array(32);
    for (let i = 0; i < 32; i++) r_group[i] = i;
    let keys = dtproto.group_crypto_derive_keys(1, r_group.buffer);

    assertEq(buf2hex(keys.k_group),
        "c429ae7559b8f8a480f68e54e0becb5ef22d142e137ab10f4dd535e3a3f777ef",
        "k_group vector");
    assertEq(buf2hex(keys.sk_bind),
        "aefb15f01c6e8c5bd3b03a9122a97b8198d69ce6138d833983f4ee46394e786b",
        "sk_bind vector");
    assertEq(buf2hex(keys.pk_bind),
        "1c37ad97463331dbcfdc44a0697482fdc00e33a6462c362980c1834f5ce16d3d",
        "pk_bind vector");

    let signature = dtproto.group_crypto_sign_uid(1, keys.sk_bind, "test-uid-001");
    assertEq(buf2hex(signature),
        "3e6d31fed3bf0bba4d06b4eb10e2de6bb419030b973bf49fd3666ff818cda4c5a42b109a431143a7e2200fb1023b9f6627303ed8ea9391de04cc056201eb8404",
        "signature vector");

    let valid = dtproto.group_crypto_verify_uid(1, keys.pk_bind, "test-uid-001", signature);
    assertEq(valid, true, "cross-platform verify");
});

// ==================== summary ====================
console.log("\n==================== Summary ====================");
console.log("Total: " + (passed + failed) + "  Passed: " + passed + "  Failed: " + failed);
if (failed > 0) process.exit(1);
