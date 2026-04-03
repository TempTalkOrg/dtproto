/// Cross-version compatibility data generator.
/// Run with BOTH old and new deps to compare deterministic outputs and capture encrypted data.
use uniffi_dtproto::{DTProto, DTCurve};
use std::collections::HashMap;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn alice_pri() -> Vec<u8> { vec![0xc8,0x06,0x43,0x9d,0xc9,0xd2,0xc4,0x76,0xff,0xed,0x8f,0x25,0x80,0xc0,0x88,0x8d,0x58,0xab,0x40,0x6b,0xf7,0xae,0x36,0x98,0x87,0x90,0x21,0xb9,0x6b,0xb4,0xbf,0x59] }
fn alice_pub() -> Vec<u8> { vec![0x1b,0xb7,0x59,0x66,0xf2,0xe9,0x3a,0x36,0x91,0xdf,0xff,0x94,0x2b,0xb2,0xa4,0x66,0xa1,0xc0,0x8b,0x8d,0x78,0xca,0x3f,0x4d,0x6d,0xf8,0xb8,0xbf,0xa2,0xe4,0xee,0x28] }
fn bob_pri() -> Vec<u8>  { vec![0xb0,0x3b,0x34,0xc3,0x3a,0x1c,0x44,0xf2,0x25,0xb6,0x62,0xd2,0xbf,0x48,0x59,0xb8,0x13,0x54,0x11,0xfa,0x7b,0x03,0x86,0xd4,0x5f,0xb7,0x5d,0xc5,0xb9,0x1b,0x44,0x66] }
fn bob_pub() -> Vec<u8>  { vec![0x65,0x36,0x14,0x99,0x3d,0x2b,0x15,0xee,0x9e,0x5f,0xd3,0xd8,0x6c,0xe7,0x19,0xef,0x4e,0xc1,0xda,0xae,0x18,0x86,0xa8,0x7b,0x3f,0x5f,0xa9,0x56,0x5a,0x27,0xa2,0x2f] }

#[test]
fn generate_all_compat_data() {
    let curve = DTCurve;
    let alice_pub_arr: [u8; 32] = alice_pub().try_into().unwrap();
    let bob_pri_arr: [u8; 32] = bob_pri().try_into().unwrap();

    // 1. Deterministic: DH shared secrets (these MUST match between versions)
    let shared_v1 = curve.dhe_key_agreement(&alice_pub_arr, &bob_pri_arr, 1);
    let shared_v3 = curve.dhe_key_agreement(&alice_pub_arr, &bob_pri_arr, 3);
    println!("DH_SHARED_V1={}", hex(&shared_v1));
    println!("DH_SHARED_V3={}", hex(&shared_v3));

    // 2. Deterministic: Public key derivation
    let bob_key = curve.from_key(&bob_pri_arr);
    println!("BOB_PUB_DERIVED={}", hex(&bob_key.derive_public_key_bytes()));

    // 3. Encrypt private chat (v1 = raw DH, compatible with old version)
    let proto_v1 = DTProto::new(1);
    let enc_msg = proto_v1.encrypt_message(
        alice_pub(), HashMap::new(), bob_pri(), b"hello cross version".to_vec(),
    ).unwrap();
    println!("MSG_CIPHER_TEXT={}", hex(&enc_msg.cipher_text));
    println!("MSG_SIGNED_E_KEY={}", hex(&enc_msg.signed_e_key));
    println!("MSG_E_KEY={}", hex(&enc_msg.e_key));
    println!("MSG_IDENTITY_KEY={}", hex(&enc_msg.identity_key));

    // Self-decrypt to verify
    let dec = proto_v1.decrypt_message(
        enc_msg.signed_e_key, enc_msg.identity_key.clone(), enc_msg.identity_key.clone(),
        Some(enc_msg.identity_key), enc_msg.e_key, alice_pri(), Vec::new(), enc_msg.cipher_text,
    ).unwrap();
    assert_eq!(dec.plain_text, b"hello cross version");

    // 4. Encrypt RTM (with fixed aes_key for reproducibility of decrypt)
    let aes_key = vec![0x42u8; 32]; // fixed key
    let enc_rtm = proto_v1.encrypt_rtm_message(
        aes_key.clone(), bob_pri(), b"hello rtm compat".to_vec(),
    ).unwrap();
    println!("RTM_CIPHER_TEXT={}", hex(&enc_rtm.cipher_text));
    println!("RTM_SIGNATURE={}", hex(&enc_rtm.signature));

    // Self-decrypt RTM
    let dec_rtm = proto_v1.decrypt_rtm_message(
        enc_rtm.signature, Some(bob_pub()), aes_key, enc_rtm.cipher_text,
    ).unwrap();
    assert_eq!(dec_rtm.plain_text, b"hello rtm compat");
    assert!(dec_rtm.verified_id_result);

    // 5. Encrypt key
    let mut pub_id_keys = HashMap::new();
    pub_id_keys.insert("alice".to_string(), alice_pub());
    let enc_key = proto_v1.encrypt_key(pub_id_keys, None).unwrap();
    println!("KEY_M_KEY={}", hex(&enc_key.m_key));
    println!("KEY_E_KEY={}", hex(&enc_key.e_key));
    println!("KEY_E_M_KEY_ALICE={}", hex(&enc_key.e_m_keys["alice"]));

    // Self-decrypt key
    let dec_key = proto_v1.decrypt_key(enc_key.e_key, alice_pri(), enc_key.e_m_keys["alice"].clone()).unwrap();
    assert_eq!(dec_key.m_key, enc_key.m_key);

    println!("ALL_SELF_CHECKS=ok");
}
