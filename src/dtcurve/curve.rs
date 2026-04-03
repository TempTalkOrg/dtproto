mod curve25519;
use rand::rngs::OsRng;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, generic_array::typenum::Unsigned},
    Aes256Gcm, Nonce, Key
};

pub const AES_GCM_NONCE_SIZE: usize = <Aes256Gcm as AeadCore>::NonceSize::USIZE;
pub const AES_GCM_TAG_SIZE: usize = <Aes256Gcm as AeadCore>::TagSize::USIZE;
pub const AES_GCM_OVERHEAD: usize = AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE;
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub const PUBLIC_KEY_LENGTH: usize = 32;
pub const SIGNATURE_LENGTH: usize = 64;
pub const CALL_KEY_LEN: usize = 64;

/// version >= HKDF_MIN_VERSION 时对 DH 输出做 HKDF 派生
pub const HKDF_MIN_VERSION: i32 = 3;

#[derive(thiserror::Error, Debug, Clone, Copy)]
#[repr(i32)]
pub enum DTProtoError {
    #[error("version error!")]
    VersionError = 1,
    #[error("params error!")]
    ParamsError = 2,
    #[error("verify signature error!")]
    VerifySignatureError = 3,
    #[error("key data length error!")]
    KeyDataLengthError = 4,
    #[error("message data length error!")]
    MessageDataLengthError = 5,
    #[error("encrypt message data error!")]
    EncryptMessageDataError = 6,
    #[error("decrypt message data error!")]
    DecryptMessageDataError = 7,
}

pub struct DTCurve;
impl DTCurve {
    pub fn verify_signature(
        &self,
        their_public_key: &[u8; curve25519::PUBLIC_KEY_LENGTH],
        message: &[u8],
        signature: &[u8; curve25519::SIGNATURE_LENGTH],
    ) -> bool {
        let messages = &[message];

        let result = curve25519::PrivateKey::verify_signature(their_public_key, messages, signature);
        return result
    }

    pub fn aes_256_gcm_encrypt(
        &self,
        ptext: &[u8], 
        key: &[u8]
    ) -> Result<Vec<u8>, DTProtoError> {

        let key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(&key);
        let nonce = Aes256Gcm::generate_nonce(&mut aes_gcm::aead::OsRng);
        let result = cipher.encrypt(&nonce, ptext);
        return match result {
            Ok(ctext) => {
                let mut new_ctext = ctext.to_vec();
                let mut nonce_data = nonce.as_slice().to_vec();
                nonce_data.append(&mut new_ctext);
                Ok(nonce_data)
            },
            Err(_) => Err(DTProtoError::EncryptMessageDataError)
        };
    }

    pub fn aes_256_gcm_decrypt(
        &self,
        ctext: &[u8], 
        key: &[u8]
    ) -> Result<Vec<u8>, DTProtoError> {

        let key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(&key);
        if ctext.len() < AES_GCM_OVERHEAD {
            return Err(DTProtoError::DecryptMessageDataError);
        }
        let nonce = Nonce::from_slice(&ctext[..AES_GCM_NONCE_SIZE]);
        let result = cipher.decrypt(nonce, &ctext[AES_GCM_NONCE_SIZE..]);
        return match result {
            Ok(plaintext) => Ok(plaintext),
            Err(_) => Err(DTProtoError::DecryptMessageDataError)
        };
    }

    /// HKDF-SHA256: extract then expand to derive a 32-byte key from input key material.
    fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
        // Extract: PRK = HMAC-SHA256(salt, IKM)
        let default_salt = [0u8; 32];
        let salt = if salt.is_empty() { &default_salt[..] } else { salt };
        let mut extract_mac = <Hmac<Sha256> as Mac>::new_from_slice(salt)
            .expect("HMAC accepts any key length");
        extract_mac.update(ikm);
        let prk = extract_mac.finalize().into_bytes();

        // Expand: OKM = HMAC-SHA256(PRK, info || 0x01)  (single block = 32 bytes)
        let mut expand_mac = <Hmac<Sha256> as Mac>::new_from_slice(&prk)
            .expect("HMAC accepts any key length");
        expand_mac.update(info);
        expand_mac.update(&[0x01u8]);
        let okm = expand_mac.finalize().into_bytes();

        let mut result = [0u8; 32];
        result.copy_from_slice(&okm);
        result
    }

    pub fn dhe_key_agreement(
        &self,
        pub_key: &[u8; curve25519::PUBLIC_KEY_LENGTH],
        priv_key: &[u8; curve25519::PRIVATE_KEY_LENGTH],
        version: i32,
    ) -> [u8; 32] {
        let private_key = curve25519::PrivateKey::from(*priv_key);
        let shared_secret = private_key.calculate_agreement(pub_key);
        if version >= HKDF_MIN_VERSION {
            Self::hkdf_sha256(&shared_secret, &[], b"dtproto-dhe")
        } else {
            shared_secret
        }
    }

    pub fn new_key_pair(
        
    ) -> curve25519::PrivateKey{
        let mut csprng = OsRng;
        curve25519::PrivateKey::new(&mut csprng)
    }

    pub fn from_key(
        &self,
        private_key: &[u8; curve25519::PRIVATE_KEY_LENGTH],
    ) -> curve25519::PrivateKey {
        curve25519::PrivateKey::from(*private_key)
    }

}