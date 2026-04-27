mod dtcurve;
mod export_neon;
mod group_crypto;
use crate::export_neon::{encrypt_message, decrypt_message, encrypt_key, decrypt_key, generate_key, decrypt_rtm_message, encrypt_rtm_message, neon_group_crypto_derive_keys, neon_group_crypto_encrypt, neon_group_crypto_decrypt, neon_group_crypto_sign_uid, neon_group_crypto_verify_uid};
pub use crate::group_crypto::{
    GroupKeySet,
    DTGroupCrypto,
};
pub use crate::dtcurve::{
    DTCurve,
    DTEncryptedMessage,
    DTDecryptedMessage,
    DTEncryptedRTMMessage,
    DTDecryptedRTMMessage,
    DTEncryptedKey,
    DTDecryptedKey,
    DTProtoError,
    DTProto,
    IdentityVerifyResult
};

fn lib_name() -> String {
    return String::from("DTProto");
}
uniffi::include_scaffolding!("dtproto");


use neon::prelude::*;
#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function("encrypt_message", encrypt_message)?;
    cx.export_function("decrypt_message", decrypt_message)?;
    cx.export_function("encrypt_key", encrypt_key)?;
    cx.export_function("decrypt_key", decrypt_key)?;
    cx.export_function("generate_key", generate_key)?;
    cx.export_function("decrypt_rtm_message", decrypt_rtm_message)?;
    cx.export_function("encrypt_rtm_message", encrypt_rtm_message)?;
    cx.export_function("group_crypto_derive_keys", neon_group_crypto_derive_keys)?;
    cx.export_function("group_crypto_encrypt", neon_group_crypto_encrypt)?;
    cx.export_function("group_crypto_decrypt", neon_group_crypto_decrypt)?;
    cx.export_function("group_crypto_sign_uid", neon_group_crypto_sign_uid)?;
    cx.export_function("group_crypto_verify_uid", neon_group_crypto_verify_uid)?;
    Ok(())
}
