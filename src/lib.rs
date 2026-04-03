mod dtcurve;
mod export_neon;
use crate::export_neon::{encrypt_message, decrypt_message, encrypt_key, decrypt_key, generate_key, decrypt_rtm_message, encrypt_rtm_message};
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
    Ok(())
}
