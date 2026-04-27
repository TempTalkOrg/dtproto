use crate::dtcurve::DTProtoError;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use sha2::Sha256;

const BLOB_VERSION_MIN: u8 = 0x01;
const BLOB_VERSION_MAX: u8 = 0x01;
const GCM_NONCE_SIZE: usize = 12;
const GCM_TAG_SIZE: usize = 16;
const BLOB_OVERHEAD: usize = 1 + GCM_NONCE_SIZE + GCM_TAG_SIZE; // version + nonce + tag
const KEY_LEN: usize = 32;
const ED25519_SIGNATURE_LEN: usize = 64;

const HKDF_SALT: &[u8] = b"tt-grp-v1|group-metadata-master";
const HKDF_INFO_K_GROUP: &[u8] = b"tt-grp-v1|aes256-gcm|key|len32";
const HKDF_INFO_ED25519_SEED: &[u8] = b"tt-grp-v1|ed25519|member-binding|seed|len32";
const SIGN_UID_PREFIX: &[u8] = b"tt-grp-v1|ed25519|uid-binding|";

#[derive(Debug)]
pub struct GroupKeySet {
    pub k_group: Vec<u8>,
    pub sk_bind: Vec<u8>,
    pub pk_bind: Vec<u8>,
}

// --- HKDF-SHA256 (extract + expand, single block = 32 bytes) ---

fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(salt).expect("HMAC accepts any key length");
    mac.update(ikm);
    mac.finalize().into_bytes().into()
}

fn hkdf_expand(prk: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(prk).expect("HMAC accepts any key length");
    mac.update(info);
    mac.update(&[0x01u8]);
    mac.finalize().into_bytes().into()
}

fn build_uid_message(uid: &str) -> Vec<u8> {
    let mut message = Vec::with_capacity(SIGN_UID_PREFIX.len() + uid.len());
    message.extend_from_slice(SIGN_UID_PREFIX);
    message.extend_from_slice(uid.as_bytes());
    message
}

// --- Public API ---

pub struct DTGroupCrypto {
    pub version: u8,
}

impl DTGroupCrypto {
    pub fn new(version: u8) -> Self {
        Self { version }
    }

    pub fn derive_keys(&self, r_group: Vec<u8>) -> Result<GroupKeySet, DTProtoError> {
        if r_group.len() != KEY_LEN {
            return Err(DTProtoError::InvalidRGroupLength);
        }

        let prk = hkdf_extract(HKDF_SALT, &r_group);
        let k_group = hkdf_expand(&prk, HKDF_INFO_K_GROUP);
        let ed25519_seed = hkdf_expand(&prk, HKDF_INFO_ED25519_SEED);

        let signing_key = SigningKey::from_bytes(&ed25519_seed);
        let verifying_key = signing_key.verifying_key();

        Ok(GroupKeySet {
            k_group: k_group.to_vec(),
            sk_bind: signing_key.to_bytes().to_vec(),
            pk_bind: verifying_key.to_bytes().to_vec(),
        })
    }

    pub fn encrypt(
        &self,
        k_group: Vec<u8>,
        plaintext: Vec<u8>,
        aad: Vec<u8>,
    ) -> Result<Vec<u8>, DTProtoError> {
        if k_group.len() != KEY_LEN {
            return Err(DTProtoError::InvalidKGroupLength);
        }
        if plaintext.is_empty() {
            return Err(DTProtoError::ParamsError);
        }
        if aad.is_empty() {
            return Err(DTProtoError::ParamsError);
        }
        if self.version < BLOB_VERSION_MIN || self.version > BLOB_VERSION_MAX {
            return Err(DTProtoError::UnsupportedBlobVersion);
        }

        // version 0x01: AES-256-GCM, blob = version(1) + nonce(12) + ciphertext + tag(16)
        let key = Key::<Aes256Gcm>::from_slice(&k_group);
        let cipher = Aes256Gcm::new(key);
        let nonce = Aes256Gcm::generate_nonce(&mut aes_gcm::aead::OsRng);

        let ciphertext_with_tag = cipher
            .encrypt(&nonce, aes_gcm::aead::Payload { msg: &plaintext, aad: &aad })
            .map_err(|_| DTProtoError::GroupEncryptError)?;

        let mut blob = Vec::with_capacity(1 + GCM_NONCE_SIZE + ciphertext_with_tag.len());
        blob.push(self.version);
        blob.extend_from_slice(nonce.as_slice());
        blob.extend_from_slice(&ciphertext_with_tag);

        Ok(blob)
    }

    pub fn decrypt(
        &self,
        k_group: Vec<u8>,
        blob: Vec<u8>,
        aad: Vec<u8>,
    ) -> Result<Vec<u8>, DTProtoError> {
        if k_group.len() != KEY_LEN {
            return Err(DTProtoError::InvalidKGroupLength);
        }
        if aad.is_empty() {
            return Err(DTProtoError::ParamsError);
        }
        if blob.len() < BLOB_OVERHEAD {
            return Err(DTProtoError::BlobTooShort);
        }
        let blob_version = blob[0];
        if blob_version < BLOB_VERSION_MIN || blob_version > BLOB_VERSION_MAX {
            return Err(DTProtoError::UnsupportedBlobVersion);
        }

        // version 0x01: AES-256-GCM
        let nonce = Nonce::from_slice(&blob[1..1 + GCM_NONCE_SIZE]);
        let ciphertext_with_tag = &blob[1 + GCM_NONCE_SIZE..];

        let key = Key::<Aes256Gcm>::from_slice(&k_group);
        let cipher = Aes256Gcm::new(key);

        cipher
            .decrypt(nonce, aes_gcm::aead::Payload { msg: ciphertext_with_tag, aad: &aad })
            .map_err(|_| DTProtoError::GroupDecryptError)
    }

    pub fn sign_uid(
        &self,
        sk_bind: Vec<u8>,
        uid: String,
    ) -> Result<Vec<u8>, DTProtoError> {
        if uid.is_empty() {
            return Err(DTProtoError::ParamsError);
        }
        let sk_bytes: [u8; KEY_LEN] = sk_bind
            .try_into()
            .map_err(|_| DTProtoError::InvalidSkBindLength)?;
        let signing_key = SigningKey::from_bytes(&sk_bytes);

        let signature = signing_key.sign(&build_uid_message(&uid));
        Ok(signature.to_bytes().to_vec())
    }

    pub fn verify_uid(
        &self,
        pk_bind: Vec<u8>,
        uid: String,
        signature: Vec<u8>,
    ) -> Result<bool, DTProtoError> {
        if uid.is_empty() {
            return Err(DTProtoError::ParamsError);
        }
        let pk_bytes: [u8; KEY_LEN] = pk_bind
            .try_into()
            .map_err(|_| DTProtoError::InvalidPkBindLength)?;
        let sig_bytes: [u8; ED25519_SIGNATURE_LEN] = signature
            .try_into()
            .map_err(|_| DTProtoError::InvalidSignatureLength)?;

        let verifying_key = VerifyingKey::from_bytes(&pk_bytes)
            .map_err(|_| DTProtoError::InvalidPkBindKey)?;
        let sig = Signature::from_bytes(&sig_bytes);

        Ok(verifying_key.verify(&build_uid_message(&uid), &sig).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gc() -> DTGroupCrypto {
        DTGroupCrypto::new(1)
    }

    #[test]
    fn test_derive_keys_deterministic() {
        let r_group = vec![0x42u8; 32];
        let keys1 = gc().derive_keys(r_group.clone()).unwrap();
        let keys2 = gc().derive_keys(r_group).unwrap();
        assert_eq!(keys1.k_group, keys2.k_group);
        assert_eq!(keys1.sk_bind, keys2.sk_bind);
        assert_eq!(keys1.pk_bind, keys2.pk_bind);
    }

    #[test]
    fn test_derive_keys_invalid_length() {
        assert_eq!(
            gc().derive_keys(vec![0u8; 16]).unwrap_err(),
            DTProtoError::InvalidRGroupLength
        );
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let r_group = vec![0xABu8; 32];
        let keys = gc().derive_keys(r_group).unwrap();
        let aad = b"tt-grp-v1|gcm|name".to_vec();
        let plaintext = "test group name".as_bytes().to_vec();

        let blob = gc().encrypt(keys.k_group.clone(), plaintext.clone(), aad.clone()).unwrap();

        // Verify blob format: version + nonce + ciphertext + tag
        assert_eq!(blob[0], 0x01);
        assert!(blob.len() >= BLOB_OVERHEAD);

        let decrypted = gc().decrypt(keys.k_group, blob, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_wrong_key() {
        let keys = gc().derive_keys(vec![0xABu8; 32]).unwrap();
        let wrong_key = vec![0xCDu8; 32];
        let aad = b"tt-grp-v1|gcm|name".to_vec();
        let plaintext = "test".as_bytes().to_vec();

        let blob = gc().encrypt(keys.k_group, plaintext, aad.clone()).unwrap();
        assert_eq!(
            gc().decrypt(wrong_key, blob, aad).unwrap_err(),
            DTProtoError::GroupDecryptError
        );
    }

    #[test]
    fn test_decrypt_wrong_aad() {
        let keys = gc().derive_keys(vec![0xABu8; 32]).unwrap();
        let aad = b"tt-grp-v1|gcm|name".to_vec();
        let wrong_aad = b"tt-grp-v1|gcm|avatar".to_vec();
        let plaintext = "test".as_bytes().to_vec();

        let blob = gc().encrypt(keys.k_group.clone(), plaintext, aad).unwrap();
        assert_eq!(
            gc().decrypt(keys.k_group, blob, wrong_aad).unwrap_err(),
            DTProtoError::GroupDecryptError
        );
    }

    #[test]
    fn test_decrypt_tampered_blob() {
        let keys = gc().derive_keys(vec![0xABu8; 32]).unwrap();
        let aad = b"tt-grp-v1|gcm|name".to_vec();
        let plaintext = "test".as_bytes().to_vec();

        let mut blob = gc().encrypt(keys.k_group.clone(), plaintext, aad.clone()).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xFF;
        assert_eq!(
            gc().decrypt(keys.k_group, blob, aad).unwrap_err(),
            DTProtoError::GroupDecryptError
        );
    }

    #[test]
    fn test_decrypt_invalid_version() {
        let keys = gc().derive_keys(vec![0xABu8; 32]).unwrap();
        let aad = b"tt-grp-v1|gcm|name".to_vec();
        let plaintext = "test".as_bytes().to_vec();

        let mut blob = gc().encrypt(keys.k_group.clone(), plaintext, aad.clone()).unwrap();
        blob[0] = 0x02;
        assert_eq!(
            gc().decrypt(keys.k_group, blob, aad).unwrap_err(),
            DTProtoError::UnsupportedBlobVersion
        );
    }

    #[test]
    fn test_decrypt_blob_too_short() {
        let keys = gc().derive_keys(vec![0xABu8; 32]).unwrap();
        let aad = b"tt-grp-v1|gcm|name".to_vec();
        assert_eq!(
            gc().decrypt(keys.k_group, vec![0x01; 10], aad).unwrap_err(),
            DTProtoError::BlobTooShort
        );
    }

    #[test]
    fn test_encrypt_empty_plaintext() {
        let keys = gc().derive_keys(vec![0xABu8; 32]).unwrap();
        assert_eq!(
            gc().encrypt(keys.k_group, vec![], b"tt-grp-v1|gcm|name".to_vec()).unwrap_err(),
            DTProtoError::ParamsError
        );
    }

    #[test]
    fn test_encrypt_empty_aad() {
        let keys = gc().derive_keys(vec![0xABu8; 32]).unwrap();
        assert_eq!(
            gc().encrypt(keys.k_group, b"test".to_vec(), vec![]).unwrap_err(),
            DTProtoError::ParamsError
        );
    }

    #[test]
    fn test_decrypt_empty_aad() {
        let keys = gc().derive_keys(vec![0xABu8; 32]).unwrap();
        assert_eq!(
            gc().decrypt(keys.k_group, vec![0x01; 30], vec![]).unwrap_err(),
            DTProtoError::ParamsError
        );
    }

    #[test]
    fn test_encrypt_unsupported_version() {
        let keys = gc().derive_keys(vec![0xABu8; 32]).unwrap();
        assert_eq!(
            DTGroupCrypto::new(0).encrypt(keys.k_group, b"test".to_vec(), b"aad".to_vec()).unwrap_err(),
            DTProtoError::UnsupportedBlobVersion
        );
    }

    #[test]
    fn test_encrypt_invalid_key_length() {
        assert_eq!(
            gc().encrypt(vec![0u8; 16], b"test".to_vec(), b"aad".to_vec()).unwrap_err(),
            DTProtoError::InvalidKGroupLength
        );
    }

    #[test]
    fn test_decrypt_invalid_key_length() {
        assert_eq!(
            gc().decrypt(vec![0u8; 16], vec![0x01; 30], b"aad".to_vec()).unwrap_err(),
            DTProtoError::InvalidKGroupLength
        );
    }

    #[test]
    fn test_sign_verify_uid() {
        let keys = gc().derive_keys(vec![0xABu8; 32]).unwrap();
        let uid = "user123".to_string();

        let signature = gc().sign_uid(keys.sk_bind, uid.clone()).unwrap();
        assert_eq!(signature.len(), ED25519_SIGNATURE_LEN);

        let valid = gc().verify_uid(keys.pk_bind, uid, signature).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_verify_uid_wrong_pk() {
        let keys = gc().derive_keys(vec![0xABu8; 32]).unwrap();
        let wrong_keys = gc().derive_keys(vec![0xCDu8; 32]).unwrap();
        let uid = "user123".to_string();

        let signature = gc().sign_uid(keys.sk_bind, uid.clone()).unwrap();
        let valid = gc().verify_uid(wrong_keys.pk_bind, uid, signature).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_verify_uid_wrong_uid() {
        let keys = gc().derive_keys(vec![0xABu8; 32]).unwrap();

        let signature = gc().sign_uid(keys.sk_bind, "user123".to_string()).unwrap();
        let valid = gc().verify_uid(keys.pk_bind, "hacker456".to_string(), signature).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_verify_uid_tampered_signature() {
        let keys = gc().derive_keys(vec![0xABu8; 32]).unwrap();
        let uid = "user123".to_string();

        let mut signature = gc().sign_uid(keys.sk_bind, uid.clone()).unwrap();
        signature[0] ^= 0xFF;
        let valid = gc().verify_uid(keys.pk_bind, uid, signature).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_verify_uid_wrong_signature_length() {
        let keys = gc().derive_keys(vec![0xABu8; 32]).unwrap();
        assert_eq!(
            gc().verify_uid(keys.pk_bind, "user123".to_string(), vec![0u8; 32]).unwrap_err(),
            DTProtoError::InvalidSignatureLength
        );
    }

    #[test]
    fn test_verify_uid_invalid_pk_length() {
        assert_eq!(
            gc().verify_uid(vec![0u8; 16], "user123".to_string(), vec![0u8; 64]).unwrap_err(),
            DTProtoError::InvalidPkBindLength
        );
    }

    #[test]
    fn test_sign_uid_empty_uid() {
        let keys = gc().derive_keys(vec![0xABu8; 32]).unwrap();
        assert_eq!(
            gc().sign_uid(keys.sk_bind, "".to_string()).unwrap_err(),
            DTProtoError::ParamsError
        );
    }

    #[test]
    fn test_verify_uid_empty_uid() {
        let keys = gc().derive_keys(vec![0xABu8; 32]).unwrap();
        assert_eq!(
            gc().verify_uid(keys.pk_bind, "".to_string(), vec![0u8; 64]).unwrap_err(),
            DTProtoError::ParamsError
        );
    }

    #[test]
    fn test_sign_uid_invalid_sk_length() {
        assert_eq!(
            gc().sign_uid(vec![0u8; 16], "user123".to_string()).unwrap_err(),
            DTProtoError::InvalidSkBindLength
        );
    }

    /// Cross-platform test vector.
    /// Other platforms MUST produce identical outputs for the same R_group.
    #[test]
    fn test_cross_platform_vector() {
        let r_group: Vec<u8> = (0u8..32).collect();
        let keys = gc().derive_keys(r_group).unwrap();

        assert_eq!(
            keys.k_group,
            [0xc4, 0x29, 0xae, 0x75, 0x59, 0xb8, 0xf8, 0xa4, 0x80, 0xf6, 0x8e, 0x54, 0xe0, 0xbe, 0xcb, 0x5e,
             0xf2, 0x2d, 0x14, 0x2e, 0x13, 0x7a, 0xb1, 0x0f, 0x4d, 0xd5, 0x35, 0xe3, 0xa3, 0xf7, 0x77, 0xef]
        );
        assert_eq!(
            keys.sk_bind,
            [0xae, 0xfb, 0x15, 0xf0, 0x1c, 0x6e, 0x8c, 0x5b, 0xd3, 0xb0, 0x3a, 0x91, 0x22, 0xa9, 0x7b, 0x81,
             0x98, 0xd6, 0x9c, 0xe6, 0x13, 0x8d, 0x83, 0x39, 0x83, 0xf4, 0xee, 0x46, 0x39, 0x4e, 0x78, 0x6b]
        );
        assert_eq!(
            keys.pk_bind,
            [0x1c, 0x37, 0xad, 0x97, 0x46, 0x33, 0x31, 0xdb, 0xcf, 0xdc, 0x44, 0xa0, 0x69, 0x74, 0x82, 0xfd,
             0xc0, 0x0e, 0x33, 0xa6, 0x46, 0x2c, 0x36, 0x29, 0x80, 0xc1, 0x83, 0x4f, 0x5c, 0xe1, 0x6d, 0x3d]
        );

        let uid = "test-uid-001".to_string();
        let signature = gc().sign_uid(keys.sk_bind.clone(), uid.clone()).unwrap();
        assert_eq!(
            signature,
            [0x3e, 0x6d, 0x31, 0xfe, 0xd3, 0xbf, 0x0b, 0xba, 0x4d, 0x06, 0xb4, 0xeb, 0x10, 0xe2, 0xde, 0x6b,
             0xb4, 0x19, 0x03, 0x0b, 0x97, 0x3b, 0xf4, 0x9f, 0xd3, 0x66, 0x6f, 0xf8, 0x18, 0xcd, 0xa4, 0xc5,
             0xa4, 0x2b, 0x10, 0x9a, 0x43, 0x11, 0x43, 0xa7, 0xe2, 0x20, 0x0f, 0xb1, 0x02, 0x3b, 0x9f, 0x66,
             0x27, 0x30, 0x3e, 0xd8, 0xea, 0x93, 0x91, 0xde, 0x04, 0xcc, 0x05, 0x62, 0x01, 0xeb, 0x84, 0x04]
        );
        assert!(gc().verify_uid(keys.pk_bind, uid, signature).unwrap());
    }
}
