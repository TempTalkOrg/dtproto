use uniffi_dtproto::{DTProto, DTCurve, IdentityVerifyResult};
use std::collections::HashMap;

#[test]
fn test_private_chat_encrypt_decrypt() {
    let sender_key_pair = DTCurve::new_key_pair();
    let sender_pri_key = sender_key_pair.private_key_bytes();

    let receiver_key_pair = DTCurve::new_key_pair();
    let receiver_pri_key = receiver_key_pair.private_key_bytes();
    let receiver_pub_key = receiver_key_pair.derive_public_key_bytes();

    let proto = DTProto::new(3);
    let plain_text = b"hello private chat".to_vec();

    let encrypted = proto.encrypt_message(
        receiver_pub_key.to_vec(),
        HashMap::new(),
        sender_pri_key.to_vec(),
        plain_text.clone(),
    ).unwrap();

    let decrypted = proto.decrypt_message(
        encrypted.signed_e_key,
        encrypted.identity_key.clone(),
        encrypted.identity_key.clone(),
        Some(encrypted.identity_key),
        encrypted.e_key,
        receiver_pri_key.to_vec(),
        Vec::new(),
        encrypted.cipher_text,
    ).unwrap();

    assert_eq!(decrypted.plain_text, plain_text);
    assert!(matches!(decrypted.identity_verify_result, IdentityVerifyResult::Match));
}

#[test]
fn test_group_chat_encrypt_decrypt() {
    let sender_key_pair = DTCurve::new_key_pair();
    let sender_pri_key = sender_key_pair.private_key_bytes();

    let receiver1_key_pair = DTCurve::new_key_pair();
    let receiver1_pri_key = receiver1_key_pair.private_key_bytes();
    let receiver1_pub_key = receiver1_key_pair.derive_public_key_bytes();

    let receiver2_key_pair = DTCurve::new_key_pair();
    let receiver2_pub_key = receiver2_key_pair.derive_public_key_bytes();

    let proto = DTProto::new(3);
    let plain_text = b"hello group chat".to_vec();

    let mut pub_id_keys = HashMap::new();
    pub_id_keys.insert("user1".to_string(), receiver1_pub_key.to_vec());
    pub_id_keys.insert("user2".to_string(), receiver2_pub_key.to_vec());

    let encrypted = proto.encrypt_message(
        Vec::new(),
        pub_id_keys,
        sender_pri_key.to_vec(),
        plain_text.clone(),
    ).unwrap();

    assert!(encrypted.erm_keys.is_some());
    let erm_keys = encrypted.erm_keys.unwrap();
    assert!(erm_keys.contains_key("user1"));
    assert!(erm_keys.contains_key("user2"));

    let decrypted = proto.decrypt_message(
        encrypted.signed_e_key,
        encrypted.identity_key.clone(),
        encrypted.identity_key.clone(),
        None,
        encrypted.e_key,
        receiver1_pri_key.to_vec(),
        erm_keys["user1"].clone(),
        encrypted.cipher_text,
    ).unwrap();

    assert_eq!(decrypted.plain_text, plain_text);
    assert!(matches!(decrypted.identity_verify_result, IdentityVerifyResult::Match));
}

#[test]
fn test_identity_verify_cache_outdated() {
    let sender_key_pair = DTCurve::new_key_pair();
    let sender_pri_key = sender_key_pair.private_key_bytes();

    let receiver_key_pair = DTCurve::new_key_pair();
    let receiver_pri_key = receiver_key_pair.private_key_bytes();
    let receiver_pub_key = receiver_key_pair.derive_public_key_bytes();

    let old_cached_key = DTCurve::new_key_pair().derive_public_key_bytes();

    let proto = DTProto::new(3);

    let encrypted = proto.encrypt_message(
        receiver_pub_key.to_vec(),
        HashMap::new(),
        sender_pri_key.to_vec(),
        b"test".to_vec(),
    ).unwrap();

    // msg == server, msg != cache → CacheOutdated
    let decrypted = proto.decrypt_message(
        encrypted.signed_e_key,
        encrypted.identity_key.clone(),
        encrypted.identity_key.clone(),
        Some(old_cached_key.to_vec()),
        encrypted.e_key,
        receiver_pri_key.to_vec(),
        Vec::new(),
        encrypted.cipher_text,
    ).unwrap();

    assert!(matches!(decrypted.identity_verify_result, IdentityVerifyResult::CacheOutdated));
}

#[test]
fn test_identity_verify_sender_key_updated() {
    let sender_key_pair = DTCurve::new_key_pair();
    let sender_pri_key = sender_key_pair.private_key_bytes();
    let sender_pub_key = sender_key_pair.derive_public_key_bytes();

    let receiver_key_pair = DTCurve::new_key_pair();
    let receiver_pri_key = receiver_key_pair.private_key_bytes();
    let receiver_pub_key = receiver_key_pair.derive_public_key_bytes();

    let new_server_key = DTCurve::new_key_pair().derive_public_key_bytes();

    let proto = DTProto::new(3);

    let encrypted = proto.encrypt_message(
        receiver_pub_key.to_vec(),
        HashMap::new(),
        sender_pri_key.to_vec(),
        b"test".to_vec(),
    ).unwrap();

    // msg != server(new), msg == cache(old) → SenderKeyUpdated
    let decrypted = proto.decrypt_message(
        encrypted.signed_e_key,
        encrypted.identity_key.clone(),
        new_server_key.to_vec(),
        Some(sender_pub_key.to_vec()),
        encrypted.e_key,
        receiver_pri_key.to_vec(),
        Vec::new(),
        encrypted.cipher_text,
    ).unwrap();

    assert!(matches!(decrypted.identity_verify_result, IdentityVerifyResult::SenderKeyUpdated));
}

#[test]
fn test_identity_verify_all_mismatch() {
    let sender_key_pair = DTCurve::new_key_pair();
    let sender_pri_key = sender_key_pair.private_key_bytes();

    let receiver_key_pair = DTCurve::new_key_pair();
    let receiver_pri_key = receiver_key_pair.private_key_bytes();
    let receiver_pub_key = receiver_key_pair.derive_public_key_bytes();

    let fake_server_key = DTCurve::new_key_pair().derive_public_key_bytes();
    let fake_cached_key = DTCurve::new_key_pair().derive_public_key_bytes();

    let proto = DTProto::new(3);

    let encrypted = proto.encrypt_message(
        receiver_pub_key.to_vec(),
        HashMap::new(),
        sender_pri_key.to_vec(),
        b"test".to_vec(),
    ).unwrap();

    // msg != server, msg != cache → AllMismatch
    let decrypted = proto.decrypt_message(
        encrypted.signed_e_key,
        encrypted.identity_key,
        fake_server_key.to_vec(),
        Some(fake_cached_key.to_vec()),
        encrypted.e_key,
        receiver_pri_key.to_vec(),
        Vec::new(),
        encrypted.cipher_text,
    ).unwrap();

    assert!(matches!(decrypted.identity_verify_result, IdentityVerifyResult::AllMismatch));
}

#[test]
fn test_signature_verification_failure() {
    let sender_key_pair = DTCurve::new_key_pair();
    let sender_pri_key = sender_key_pair.private_key_bytes();

    let receiver_key_pair = DTCurve::new_key_pair();
    let receiver_pri_key = receiver_key_pair.private_key_bytes();
    let receiver_pub_key = receiver_key_pair.derive_public_key_bytes();

    let proto = DTProto::new(3);

    let encrypted = proto.encrypt_message(
        receiver_pub_key.to_vec(),
        HashMap::new(),
        sender_pri_key.to_vec(),
        b"test".to_vec(),
    ).unwrap();

    // Tamper with signed_e_key to cause signature verification failure
    let mut tampered_sig = encrypted.signed_e_key.clone();
    tampered_sig[0] ^= 0xFF;

    let result = proto.decrypt_message(
        tampered_sig,
        encrypted.identity_key.clone(),
        encrypted.identity_key,
        None,
        encrypted.e_key,
        receiver_pri_key.to_vec(),
        Vec::new(),
        encrypted.cipher_text,
    );

    assert!(result.is_err());
}

#[test]
fn test_encrypt_decrypt_key() {
    let receiver_key_pair = DTCurve::new_key_pair();
    let receiver_pri_key = receiver_key_pair.private_key_bytes();
    let receiver_pub_key = receiver_key_pair.derive_public_key_bytes();

    let proto = DTProto::new(3);

    let mut pub_id_keys = HashMap::new();
    pub_id_keys.insert("user1".to_string(), receiver_pub_key.to_vec());

    let encrypted_key = proto.encrypt_key(pub_id_keys, None).unwrap();

    assert_eq!(encrypted_key.m_key.len(), 64);
    assert!(encrypted_key.e_m_keys.contains_key("user1"));

    let decrypted_key = proto.decrypt_key(
        encrypted_key.e_key,
        receiver_pri_key.to_vec(),
        encrypted_key.e_m_keys["user1"].clone(),
    ).unwrap();

    assert_eq!(decrypted_key.m_key, encrypted_key.m_key);
}

#[test]
fn test_encrypt_key_with_existing_m_key() {
    let receiver_key_pair = DTCurve::new_key_pair();
    let receiver_pri_key = receiver_key_pair.private_key_bytes();
    let receiver_pub_key = receiver_key_pair.derive_public_key_bytes();

    let proto = DTProto::new(3);
    let existing_m_key = proto.generate_key();

    let mut pub_id_keys = HashMap::new();
    pub_id_keys.insert("user1".to_string(), receiver_pub_key.to_vec());

    let encrypted_key = proto.encrypt_key(pub_id_keys, Some(existing_m_key.clone())).unwrap();
    assert_eq!(encrypted_key.m_key, existing_m_key);

    let decrypted_key = proto.decrypt_key(
        encrypted_key.e_key,
        receiver_pri_key.to_vec(),
        encrypted_key.e_m_keys["user1"].clone(),
    ).unwrap();

    assert_eq!(decrypted_key.m_key, existing_m_key);
}

#[test]
fn test_rtm_encrypt_decrypt() {
    let sender_key_pair = DTCurve::new_key_pair();
    let sender_pri_key = sender_key_pair.private_key_bytes();
    let sender_pub_key = sender_key_pair.derive_public_key_bytes();

    let proto = DTProto::new(3);
    let aes_key = proto.generate_key()[..32].to_vec();
    let plain_text = b"hello rtm".to_vec();

    let encrypted = proto.encrypt_rtm_message(
        aes_key.clone(),
        sender_pri_key.to_vec(),
        plain_text.clone(),
    ).unwrap();

    let decrypted = proto.decrypt_rtm_message(
        encrypted.signature,
        Some(sender_pub_key.to_vec()),
        aes_key,
        encrypted.cipher_text,
    ).unwrap();

    assert_eq!(decrypted.plain_text, plain_text);
    assert!(decrypted.verified_id_result);
}

#[test]
fn test_rtm_decrypt_without_id_key() {
    let sender_key_pair = DTCurve::new_key_pair();
    let sender_pri_key = sender_key_pair.private_key_bytes();

    let proto = DTProto::new(3);
    let aes_key = proto.generate_key()[..32].to_vec();
    let plain_text = b"hello rtm no verify".to_vec();

    let encrypted = proto.encrypt_rtm_message(
        aes_key.clone(),
        sender_pri_key.to_vec(),
        plain_text.clone(),
    ).unwrap();

    let decrypted = proto.decrypt_rtm_message(
        encrypted.signature,
        None,
        aes_key,
        encrypted.cipher_text,
    ).unwrap();

    assert_eq!(decrypted.plain_text, plain_text);
    assert!(!decrypted.verified_id_result);
}

#[test]
fn test_generate_key() {
    let proto = DTProto::new(3);
    let key = proto.generate_key();
    assert_eq!(key.len(), 64);

    let key2 = proto.generate_key();
    assert_ne!(key, key2);
}

#[test]
fn test_version_error() {
    let proto = DTProto::new(0);
    let result = proto.encrypt_message(
        vec![0u8; 32],
        HashMap::new(),
        vec![0u8; 32],
        b"test".to_vec(),
    );
    assert!(result.is_err());
}

#[test]
fn test_v1_backward_compatible() {
    let sender_key_pair = DTCurve::new_key_pair();
    let sender_pri_key = sender_key_pair.private_key_bytes();

    let receiver_key_pair = DTCurve::new_key_pair();
    let receiver_pri_key = receiver_key_pair.private_key_bytes();
    let receiver_pub_key = receiver_key_pair.derive_public_key_bytes();

    let proto_v1 = DTProto::new(1);
    let plain_text = b"v1 message".to_vec();

    let encrypted = proto_v1.encrypt_message(
        receiver_pub_key.to_vec(),
        HashMap::new(),
        sender_pri_key.to_vec(),
        plain_text.clone(),
    ).unwrap();

    let decrypted = proto_v1.decrypt_message(
        encrypted.signed_e_key,
        encrypted.identity_key.clone(),
        encrypted.identity_key,
        None,
        encrypted.e_key,
        receiver_pri_key.to_vec(),
        Vec::new(),
        encrypted.cipher_text,
    ).unwrap();

    assert_eq!(decrypted.plain_text, plain_text);
}

#[test]
fn test_v2_backward_compatible() {
    let sender_key_pair = DTCurve::new_key_pair();
    let sender_pri_key = sender_key_pair.private_key_bytes();

    let receiver_key_pair = DTCurve::new_key_pair();
    let receiver_pri_key = receiver_key_pair.private_key_bytes();
    let receiver_pub_key = receiver_key_pair.derive_public_key_bytes();

    let proto_v2 = DTProto::new(2);
    let plain_text = b"v2 message".to_vec();

    let encrypted = proto_v2.encrypt_message(
        receiver_pub_key.to_vec(),
        HashMap::new(),
        sender_pri_key.to_vec(),
        plain_text.clone(),
    ).unwrap();

    let decrypted = proto_v2.decrypt_message(
        encrypted.signed_e_key,
        encrypted.identity_key.clone(),
        encrypted.identity_key,
        None,
        encrypted.e_key,
        receiver_pri_key.to_vec(),
        Vec::new(),
        encrypted.cipher_text,
    ).unwrap();

    assert_eq!(decrypted.plain_text, plain_text);
}
