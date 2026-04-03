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

// ==================== summary ====================
console.log("\n==================== Summary ====================");
console.log("Total: " + (passed + failed) + "  Passed: " + passed + "  Failed: " + failed);
if (failed > 0) process.exit(1);
