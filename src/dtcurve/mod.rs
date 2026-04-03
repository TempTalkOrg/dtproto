mod curve;
pub use curve::{DTCurve, DTProtoError};
use arrayref::array_ref;
use rand::rngs::OsRng;
use rand::Rng;
use std::collections::HashMap;
use subtle::ConstantTimeEq;

pub struct DTEncryptedMessage {
    pub cipher_text: Vec<u8>, 
    pub signed_e_key: Vec<u8>, 
    pub e_key: Vec<u8>, 
    pub identity_key: Vec<u8>, 
    pub erm_keys: Option<HashMap<String, Vec<u8>>>
}

pub enum IdentityVerifyResult {
    Match,
    CacheOutdated,
    SenderKeyUpdated,
    AllMismatch,
}

pub struct DTDecryptedMessage {
    pub plain_text: Vec<u8>,
    pub identity_verify_result: IdentityVerifyResult,
}

pub struct DTEncryptedRTMMessage {
    pub cipher_text: Vec<u8>, 
    pub signature: Vec<u8>
}

pub struct DTDecryptedRTMMessage {
    pub plain_text: Vec<u8>, 
    pub verified_id_result: bool
}

#[derive(Debug)]
pub struct DTEncryptedKey {
    pub m_key: Vec<u8>, 
    pub e_m_keys: HashMap<String, Vec<u8>>, 
    pub e_key: Vec<u8>
}

#[derive(Debug)]
pub struct DTDecryptedKey {
    pub m_key: Vec<u8>
}

pub const MESSAGE_KEY_LEN: usize = 32;
pub struct DTProto {
    pub version: i32
}
impl DTProto {
    pub fn new(version: i32) -> Self {
        DTProto { version: version }
    }

    pub fn decrypt_message(
        &self,
        signed_e_key: Vec<u8>,
        their_id_key: Vec<u8>,
        local_their_id_key: Vec<u8>,
        cached_their_id_key: Option<Vec<u8>>,
        e_key: Vec<u8>,
        local_pri_key: Vec<u8>,
        erm_key: Vec<u8>,
        cipher_text: Vec<u8>
        ) -> Result<DTDecryptedMessage, DTProtoError> {

            if self.version <= 0 {
                return Err(DTProtoError::VersionError);
            }

            if signed_e_key.len() != curve::SIGNATURE_LENGTH || their_id_key.len() != MESSAGE_KEY_LEN || e_key.len() != MESSAGE_KEY_LEN || local_pri_key.len() != MESSAGE_KEY_LEN {
                return Err(DTProtoError::KeyDataLengthError);
            }

            if local_their_id_key.len() != MESSAGE_KEY_LEN {
                return Err(DTProtoError::KeyDataLengthError);
            }

            if let Some(ref cached_key) = cached_their_id_key {
                if cached_key.len() != MESSAGE_KEY_LEN {
                    return Err(DTProtoError::KeyDataLengthError);
                }
            }

            if cipher_text.len() == 0 {
                return Err(DTProtoError::MessageDataLengthError);
            }

            let curve = DTCurve;

            let sig_valid = curve.verify_signature(
                array_ref![their_id_key, 0, curve::PUBLIC_KEY_LENGTH],
                &e_key,
                array_ref![signed_e_key, 0, curve::SIGNATURE_LENGTH]);
            if !sig_valid {
                return Err(DTProtoError::VerifySignatureError);
            }

            let msg_matches_server = bool::from(their_id_key.ct_eq(&local_their_id_key));
            let identity_verify_result = match &cached_their_id_key {
                Some(cached_key) => {
                    let msg_matches_cached = bool::from(their_id_key.ct_eq(cached_key));
                    match (msg_matches_server, msg_matches_cached) {
                        (true, true)   => IdentityVerifyResult::Match,
                        (true, false)  => IdentityVerifyResult::CacheOutdated,
                        (false, true)  => IdentityVerifyResult::SenderKeyUpdated,
                        (false, false) => IdentityVerifyResult::AllMismatch,
                    }
                },
                None => {
                    if msg_matches_server {
                        IdentityVerifyResult::Match
                    } else {
                        IdentityVerifyResult::AllMismatch
                    }
                }
            };

            let m_key = curve.dhe_key_agreement(
                array_ref![e_key, 0, MESSAGE_KEY_LEN],
                array_ref![local_pri_key, 0, MESSAGE_KEY_LEN],
                self.version
            );
            let plain_text = if erm_key.len() > 0 {
                if erm_key.len() < curve::AES_GCM_OVERHEAD {
                    return Err(DTProtoError::KeyDataLengthError);
                }
                let rm_key = curve.aes_256_gcm_decrypt(&erm_key, &m_key)?;
                curve.aes_256_gcm_decrypt(&cipher_text, &rm_key)?
            } else {
                curve.aes_256_gcm_decrypt(&cipher_text, &m_key)?
            };

            Ok(DTDecryptedMessage {
                plain_text,
                identity_verify_result,
            })

    }

    pub fn encrypt_message(
        &self,
        pub_id_key: Vec<u8>,
        pub_id_keys: HashMap<String, Vec<u8>>,
        local_pri_key: Vec<u8>,
        plain_text: Vec<u8>
        ) -> Result<DTEncryptedMessage, DTProtoError> {

            if self.version <= 0 {
                return Err(DTProtoError::VersionError);
            }

            if local_pri_key.len() != MESSAGE_KEY_LEN {
                return Err(DTProtoError::KeyDataLengthError);
            }

            if plain_text.len() == 0 {
                return Err(DTProtoError::MessageDataLengthError);
            }

            let curve = DTCurve;

            let e_key_pair = DTCurve::new_key_pair();

            let local_private_id_key = curve.from_key(array_ref![local_pri_key, 0, MESSAGE_KEY_LEN]);

            let mut csprng_sig = OsRng;
            let e_pub_key = e_key_pair.derive_public_key_bytes();
            let signature = local_private_id_key.calculate_signature(&mut csprng_sig, &[&e_pub_key]);

            if pub_id_key.len() > 0 {

                if pub_id_key.len() != MESSAGE_KEY_LEN {
                    return Err(DTProtoError::KeyDataLengthError);
                }

                let m_key = curve.dhe_key_agreement(
                    array_ref![pub_id_key, 0, MESSAGE_KEY_LEN],
                    &e_key_pair.private_key_bytes(),
                    self.version
                );
                let em = curve.aes_256_gcm_encrypt(&plain_text, &m_key)?;

                let encrypted_message = DTEncryptedMessage {
                    cipher_text: em, 
                    signed_e_key: signature.to_vec(), 
                    e_key: e_key_pair.derive_public_key_bytes().to_vec(), 
                    identity_key: local_private_id_key.derive_public_key_bytes().to_vec(), 
                    erm_keys: None,
                };
                return Ok(encrypted_message);

            } else if pub_id_keys.len() > 0 {

                let mut rm_key = [0u8; MESSAGE_KEY_LEN];
                OsRng.fill(&mut rm_key);
                let em = curve.aes_256_gcm_encrypt(&plain_text, &rm_key)?;
                let mut erm_keys: HashMap<String, Vec<u8>> = HashMap::new();
                for (uid, id_key) in pub_id_keys {
                    if id_key.len() != MESSAGE_KEY_LEN {
                        return Err(DTProtoError::KeyDataLengthError);
                    }
                    let m_key = curve.dhe_key_agreement(
                        array_ref![id_key, 0, MESSAGE_KEY_LEN],
                        &e_key_pair.private_key_bytes(),
                        self.version
                    );
                    let erm_key = curve.aes_256_gcm_encrypt(&rm_key, &m_key)?;
                    erm_keys.insert(uid, erm_key);
                }

                let encrypted_message = DTEncryptedMessage {
                    cipher_text: em, 
                    signed_e_key: signature.to_vec(), 
                    e_key: e_key_pair.derive_public_key_bytes().to_vec(), 
                    identity_key: local_private_id_key.derive_public_key_bytes().to_vec(), 
                    erm_keys: Some(erm_keys),
                };

                Ok(encrypted_message)

            } else {
                Err(DTProtoError::ParamsError)
            }


    }

    pub fn decrypt_key(
        &self, 
        e_key: Vec<u8>, 
        local_pri_key: Vec<u8>, 
        e_m_key: Vec<u8>
        ) -> Result<DTDecryptedKey, DTProtoError> {

            if self.version <= 0 {
                return Err(DTProtoError::VersionError);
            }

            if e_key.len() != MESSAGE_KEY_LEN || local_pri_key.len() != MESSAGE_KEY_LEN {
                return Err(DTProtoError::KeyDataLengthError);
            }

            if e_m_key.len() < curve::AES_GCM_OVERHEAD {
                return Err(DTProtoError::MessageDataLengthError);
            }

            let curve = DTCurve;
        
            let key_key = curve.dhe_key_agreement(
                array_ref![e_key, 0, MESSAGE_KEY_LEN],
                array_ref![local_pri_key, 0, MESSAGE_KEY_LEN],
                self.version
            );

            let m_key = curve.aes_256_gcm_decrypt(&e_m_key, &key_key)?;
            let decrypted_key: DTDecryptedKey = DTDecryptedKey { 
                m_key: m_key,
            };
            return Ok(decrypted_key);


        }


        fn generate_key_bytes() -> [u8; 64] {
            let mut key = [0u8; 64];
            OsRng.fill(&mut key);
            key
        }

        pub fn generate_key(&self) -> Vec<u8> {
            Self::generate_key_bytes().to_vec()
        }

        pub fn encrypt_key(
            &self, 
            pub_id_keys: HashMap<String, Vec<u8>>,
            m_key: Option<Vec<u8>>
            ) -> Result<DTEncryptedKey, DTProtoError> {
    
                if self.version <= 0 {
                    return Err(DTProtoError::VersionError);
                }

                let curve = DTCurve;
                let e_key_pair = DTCurve::new_key_pair();
                let mut new_m_key = Self::generate_key_bytes();
                if let Some(m_key_value) = m_key {
                    if m_key_value.len() != curve::CALL_KEY_LEN {
                        return Err(DTProtoError::KeyDataLengthError);
                    }
                    new_m_key.copy_from_slice(&m_key_value);
                }

                if pub_id_keys.is_empty() {
                    Err(DTProtoError::ParamsError)
                } else {
                    let mut e_m_keys: HashMap<String, Vec<u8>> = HashMap::new();
                    for (uid, id_key) in pub_id_keys {
                        if id_key.len() != MESSAGE_KEY_LEN {
                            return Err(DTProtoError::KeyDataLengthError);
                        }
                        let key_key = curve.dhe_key_agreement(
                            array_ref![id_key, 0, MESSAGE_KEY_LEN],
                            &e_key_pair.private_key_bytes(),
                            self.version
                        );
                        let e_m_key = curve.aes_256_gcm_encrypt(&new_m_key, &key_key)?;
                        e_m_keys.insert(uid, e_m_key);
                    }
                    let encrypted_key: DTEncryptedKey = DTEncryptedKey { 
                        m_key: new_m_key.to_vec(),
                        e_m_keys: e_m_keys,
                        e_key: e_key_pair.derive_public_key_bytes().to_vec() 
                    };
    
                    Ok(encrypted_key)
                }
    

    
        }

        pub fn decrypt_rtm_message(
            &self, 
            signature: Vec<u8>, 
            their_local_id_key: Option<Vec<u8>>,
            aes_key: Vec<u8>, 
            cipher_text: Vec<u8>
            ) -> Result<DTDecryptedRTMMessage, DTProtoError> {
    
                if self.version <= 0 {
                    return Err(DTProtoError::VersionError);
                }
    
                if signature.len() != curve::SIGNATURE_LENGTH || aes_key.len() != MESSAGE_KEY_LEN {
                    return Err(DTProtoError::KeyDataLengthError);
                }
    
                if cipher_text.len() == 0 {
                    return Err(DTProtoError::MessageDataLengthError);
                }
    
                let curve = DTCurve;
    
                let mut verified_id_result = false;
                if let Some(their_id_key_value) = their_local_id_key {
                    if their_id_key_value.len() != MESSAGE_KEY_LEN {
                        return Err(DTProtoError::KeyDataLengthError);
                    } else {
                        if curve.verify_signature(array_ref![their_id_key_value, 0, curve::PUBLIC_KEY_LENGTH], 
                            &cipher_text,
                            array_ref![signature, 0, curve::SIGNATURE_LENGTH]) {
                            verified_id_result = true;
                        }
                    }
                }
                
            
                let plain_text = curve.aes_256_gcm_decrypt(&cipher_text, &aes_key)?;
                let decrypted_message = DTDecryptedRTMMessage {
                    plain_text: plain_text, 
                    verified_id_result: verified_id_result
                };
                return Ok(decrypted_message);
    
        }
    
        pub fn encrypt_rtm_message(
            &self, 
            aes_key: Vec<u8>,
            local_pri_key: Vec<u8>, 
            plain_text: Vec<u8>
            ) -> Result<DTEncryptedRTMMessage, DTProtoError> {
    
                if self.version <= 0 {
                    return Err(DTProtoError::VersionError);
                }
    
                if local_pri_key.len() != MESSAGE_KEY_LEN || aes_key.len() != MESSAGE_KEY_LEN {
                    return Err(DTProtoError::KeyDataLengthError);
                }
    
                if plain_text.len() == 0 {
                    return Err(DTProtoError::MessageDataLengthError);
                }
    
                let curve = DTCurve;
    
                let local_private_id_key = curve.from_key(array_ref![local_pri_key, 0, MESSAGE_KEY_LEN]);

                let mut csprng_sig = OsRng;

                let cipher_text = curve.aes_256_gcm_encrypt(&plain_text, &aes_key)?;

                let signature = local_private_id_key.calculate_signature(&mut csprng_sig, &[&cipher_text]);

                let encrypted_rtm_message = DTEncryptedRTMMessage {
                    cipher_text: cipher_text, 
                    signature: signature.to_vec()
                };
                return Ok(encrypted_rtm_message);
    
        }

}