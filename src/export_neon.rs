use neon::prelude::*;
use neon::types::buffer::TypedArray;
use std::collections::HashMap;
pub use crate::dtcurve::{DTProto, DTProtoError, IdentityVerifyResult};
use crate::group_crypto;


pub fn encrypt_message(mut cx: FunctionContext) -> JsResult<JsObject> {
    let version = cx.argument::<JsNumber>(0)?.value(&mut cx);
    let pub_id_key = cx.argument::<JsArrayBuffer>(1)?.as_slice(&cx).to_vec();
    let pub_id_keys = cx.argument::<JsObject>(2)?;
    let local_pri_key = cx.argument::<JsArrayBuffer>(3)?.as_slice(&cx).to_vec();
    let plain_text = cx.argument::<JsArrayBuffer>(4)?.as_slice(&cx).to_vec();

    let proto = DTProto{version: version as i32};
    let names = pub_id_keys.get_own_property_names(&mut cx)?.to_vec(&mut cx)?;
    let mut pub_id_keys_map = HashMap::new();
    for name in  names{
        let value = pub_id_keys.get(&mut cx, name)? as Handle<'_, JsArrayBuffer>;
        let value = value.as_slice(&cx).to_vec();
        let key = name.to_string(&mut cx)?.value(&mut cx);
        pub_id_keys_map.insert(key, value);
    }
    let encrypted_message_or_error = proto.encrypt_message(pub_id_key, pub_id_keys_map, local_pri_key, plain_text);
    let encrypted_message = encrypted_message_or_error.or_else(|e| {
        let err = JsError::error(&mut cx, e.to_string())?;
        let code = cx.number(e as i32);
        err.set(&mut cx, "code", code)?;
        cx.throw(err)?;
        unreachable!()
    })?;


    let result = cx.empty_object();
    let mut cipher_text = cx.array_buffer(encrypted_message.cipher_text.len())?;
    for (i, elem) in cipher_text.as_mut_slice(&mut cx).iter_mut().enumerate() {
        *elem = encrypted_message.cipher_text[i];
    }

    let mut signed_e_key = cx.array_buffer(encrypted_message.signed_e_key.len())?;
    for (i, elem) in signed_e_key.as_mut_slice(&mut cx).iter_mut().enumerate() {
        *elem = encrypted_message.signed_e_key[i];
    }

    let mut e_key = cx.array_buffer(encrypted_message.e_key.len())?;
    for (i, elem) in e_key.as_mut_slice(&mut cx).iter_mut().enumerate() {
        *elem = encrypted_message.e_key[i];
    }

    let mut identity_key = cx.array_buffer(encrypted_message.identity_key.len())?;
    for (i, elem) in identity_key.as_mut_slice(&mut cx).iter_mut().enumerate() {
        *elem = encrypted_message.identity_key[i];
    }
   
    result.set(&mut cx, "cipher_text", cipher_text)?;
    result.set(&mut cx, "signed_e_key", signed_e_key)?;
    result.set(&mut cx, "e_key", e_key)?;
    result.set(&mut cx, "identity_key", identity_key)?;
    match encrypted_message.erm_keys {
        None => None,
        Some(erm_keys_map) => {
            let erm_keys = cx.empty_object();
            for (key, value) in erm_keys_map {
                let mut js_value = cx.array_buffer(value.len())?;
                for (i, elem) in js_value.as_mut_slice(&mut cx).iter_mut().enumerate() {
                    *elem = value[i];
                }
                erm_keys.set(&mut cx, key.as_str(), js_value)?;
            }
            result.set(&mut cx, "erm_keys", erm_keys)?;
            Some(1)
        },
    };
    Ok(result)
}

pub fn decrypt_message(mut cx: FunctionContext) -> JsResult<JsObject> {
    let version = cx.argument::<JsNumber>(0)?.value(&mut cx);
    let signed_e_key = cx.argument::<JsArrayBuffer>(1)?.as_slice(&cx).to_vec();
    let their_id_key = cx.argument::<JsArrayBuffer>(2)?.as_slice(&cx).to_vec();
    let local_their_id_key = cx.argument::<JsArrayBuffer>(3)?.as_slice(&cx).to_vec();
    let cached_their_id_key_value = cx.argument::<JsArrayBuffer>(4)?.as_slice(&cx).to_vec();
    let cached_their_id_key: Option<Vec<u8>> = if cached_their_id_key_value.is_empty() {
        None
    } else {
        Some(cached_their_id_key_value)
    };
    let e_key = cx.argument::<JsArrayBuffer>(5)?.as_slice(&cx).to_vec();
    let local_pri_key = cx.argument::<JsArrayBuffer>(6)?.as_slice(&cx).to_vec();
    let erm_key = cx.argument::<JsArrayBuffer>(7)?.as_slice(&cx).to_vec();
    let cipher_text = cx.argument::<JsArrayBuffer>(8)?.as_slice(&cx).to_vec();
    let proto = DTProto{version: version as i32};
    let decrypted_message_or_error = proto.decrypt_message(signed_e_key, their_id_key, local_their_id_key, cached_their_id_key, e_key, local_pri_key, erm_key, cipher_text);
    let decrypted_message = decrypted_message_or_error.or_else(|e| {
        let err = JsError::error(&mut cx, e.to_string())?;
        let code = cx.number(e as i32);
        err.set(&mut cx, "code", code)?;
        cx.throw(err)?;
        unreachable!()
    })?;

    let result = cx.empty_object();
    let mut plain_text = cx.array_buffer(decrypted_message.plain_text.len())?;
    for (i, elem) in plain_text.as_mut_slice(&mut cx).iter_mut().enumerate() {
        *elem = decrypted_message.plain_text[i];
    }
    let identity_verify_result = cx.number(match decrypted_message.identity_verify_result {
        IdentityVerifyResult::Match => 0,
        IdentityVerifyResult::CacheOutdated => 1,
        IdentityVerifyResult::SenderKeyUpdated => 2,
        IdentityVerifyResult::AllMismatch => 3,
    });
    result.set(&mut cx, "plain_text", plain_text)?;
    result.set(&mut cx, "identity_verify_result", identity_verify_result)?;
    Ok(result)
}


pub fn encrypt_key(mut cx: FunctionContext) -> JsResult<JsObject> {
    let version = cx.argument::<JsNumber>(0)?.value(&mut cx);
    let pub_id_keys = cx.argument::<JsObject>(1)?;
    let m_key_value = cx.argument::<JsArrayBuffer>(2)?.as_slice(&cx).to_vec();
    let m_key: Option<Vec<u8>>;
    if m_key_value.is_empty(){
        m_key = None;
    } else {
        m_key = Some(m_key_value);
    }

    let proto = DTProto{version: version as i32};

    let names= pub_id_keys.get_own_property_names(&mut cx)?.to_vec(&mut cx)?;
    let mut pub_id_keys_map = HashMap::new();
    for name in  names{
        let value = pub_id_keys.get(&mut cx, name)? as Handle<'_, JsArrayBuffer>;
        let value = value.as_slice(&cx).to_vec();
        let key = name.to_string(&mut cx)?.value(&mut cx);
        pub_id_keys_map.insert(key, value);
    }
    let encrypted_key_or_error = proto.encrypt_key(pub_id_keys_map, m_key);
    let encrypted_key = encrypted_key_or_error.or_else(|e| {
        let err = JsError::error(&mut cx, e.to_string())?;
        let code = cx.number(e as i32);
        err.set(&mut cx, "code", code)?;
        cx.throw(err)?;
        unreachable!()
    })?;

    let result = cx.empty_object();
    let mut m_key = cx.array_buffer(encrypted_key.m_key.len())?;
    for (i, elem) in m_key.as_mut_slice(&mut cx).iter_mut().enumerate() {
        *elem = encrypted_key.m_key[i];
    }

    let mut e_key = cx.array_buffer(encrypted_key.e_key.len())?;
    for (i, elem) in e_key.as_mut_slice(&mut cx).iter_mut().enumerate() {
        *elem = encrypted_key.e_key[i];
    }
   
    result.set(&mut cx, "m_key", m_key)?;
    result.set(&mut cx, "e_key", e_key)?;

    let e_m_keys = cx.empty_object();
    for (key, value) in encrypted_key.e_m_keys {
        let mut js_value = cx.array_buffer(value.len())?;
        for (i, elem) in js_value.as_mut_slice(&mut cx).iter_mut().enumerate() {
            *elem = value[i];
        }
        e_m_keys.set(&mut cx, key.as_str(), js_value)?;
    }
    result.set(&mut cx, "e_m_keys", e_m_keys)?;
    Ok(result)
}

pub fn decrypt_key(mut cx: FunctionContext) -> JsResult<JsObject> {
    let version = cx.argument::<JsNumber>(0)?.value(&mut cx);
    let e_key = cx.argument::<JsArrayBuffer>(1)?.as_slice(&cx).to_vec();
    let local_pri_key = cx.argument::<JsArrayBuffer>(2)?.as_slice(&cx).to_vec();
    let e_m_key = cx.argument::<JsArrayBuffer>(3)?.as_slice(&cx).to_vec();

    let proto = DTProto{version: version as i32};
    let decrypted_key_or_error = proto.decrypt_key(e_key, local_pri_key, e_m_key);
    let decrypted_key = decrypted_key_or_error.or_else(|e| {
        let err = JsError::error(&mut cx, e.to_string())?;
        let code = cx.number(e as i32);
        err.set(&mut cx, "code", code)?;
        cx.throw(err)?;
        unreachable!()
    })?;

    let result = cx.empty_object();
    let mut m_key = cx.array_buffer(decrypted_key.m_key.len())?;
    for (i, elem) in m_key.as_mut_slice(&mut cx).iter_mut().enumerate() {
        *elem = decrypted_key.m_key[i];
    }
    result.set(&mut cx, "m_key", m_key)?;
    Ok(result)
}

pub fn generate_key(mut cx: FunctionContext) -> JsResult<JsArrayBuffer> {
    let version = cx.argument::<JsNumber>(0)?.value(&mut cx);
    let proto = DTProto{version: version as i32};
    let new_key = proto.generate_key();
    let mut new_key_buffer = cx.array_buffer(new_key.len())?;
    for (i, elem) in new_key_buffer.as_mut_slice(&mut cx).iter_mut().enumerate() {
        *elem = new_key[i];
    }
    Ok(new_key_buffer)
}


pub fn encrypt_rtm_message(mut cx: FunctionContext) -> JsResult<JsObject> {
    let version = cx.argument::<JsNumber>(0)?.value(&mut cx);
    let aes_key = cx.argument::<JsArrayBuffer>(1)?.as_slice(&cx).to_vec();
    let local_pri_key = cx.argument::<JsArrayBuffer>(2)?.as_slice(&cx).to_vec();
    let plain_text = cx.argument::<JsArrayBuffer>(3)?.as_slice(&cx).to_vec();

    let proto = DTProto{version: version as i32};
    let encrypted_message_or_error = proto.encrypt_rtm_message(aes_key, local_pri_key, plain_text);
    let encrypted_message = encrypted_message_or_error.or_else(|e| {
        let err = JsError::error(&mut cx, e.to_string())?;
        let code = cx.number(e as i32);
        err.set(&mut cx, "code", code)?;
        cx.throw(err)?;
        unreachable!()
    })?;


    let result = cx.empty_object();
    let mut cipher_text = cx.array_buffer(encrypted_message.cipher_text.len())?;
    for (i, elem) in cipher_text.as_mut_slice(&mut cx).iter_mut().enumerate() {
        *elem = encrypted_message.cipher_text[i];
    }

    let mut signature = cx.array_buffer(encrypted_message.signature.len())?;
    for (i, elem) in signature.as_mut_slice(&mut cx).iter_mut().enumerate() {
        *elem = encrypted_message.signature[i];
    }
   
    result.set(&mut cx, "cipher_text", cipher_text)?;
    result.set(&mut cx, "signature", signature)?;
    Ok(result)
}

fn throw_proto_error<'a>(cx: &mut FunctionContext<'a>, e: DTProtoError) -> NeonResult<()> {
    let err = JsError::error(cx, e.to_string())?;
    let code = cx.number(e as i32);
    err.set(cx, "code", code)?;
    cx.throw(err)?;
    unreachable!()
}

fn vec_to_buffer<'a>(cx: &mut FunctionContext<'a>, data: &[u8]) -> JsResult<'a, JsArrayBuffer> {
    let mut buf = cx.array_buffer(data.len())?;
    buf.as_mut_slice(cx).copy_from_slice(data);
    Ok(buf)
}

pub fn neon_group_crypto_derive_keys(mut cx: FunctionContext) -> JsResult<JsObject> {
    let version = cx.argument::<JsNumber>(0)?.value(&mut cx) as u8;
    let r_group = cx.argument::<JsArrayBuffer>(1)?.as_slice(&cx).to_vec();

    let gc = group_crypto::DTGroupCrypto::new(version);
    let keys = gc.derive_keys(r_group)
        .or_else(|e| { throw_proto_error(&mut cx, e)?; unreachable!() })?;

    let result = cx.empty_object();
    let k_group = vec_to_buffer(&mut cx, &keys.k_group)?;
    let sk_bind = vec_to_buffer(&mut cx, &keys.sk_bind)?;
    let pk_bind = vec_to_buffer(&mut cx, &keys.pk_bind)?;
    result.set(&mut cx, "k_group", k_group)?;
    result.set(&mut cx, "sk_bind", sk_bind)?;
    result.set(&mut cx, "pk_bind", pk_bind)?;
    Ok(result)
}

pub fn neon_group_crypto_encrypt(mut cx: FunctionContext) -> JsResult<JsArrayBuffer> {
    let version = cx.argument::<JsNumber>(0)?.value(&mut cx) as u8;
    let k_group = cx.argument::<JsArrayBuffer>(1)?.as_slice(&cx).to_vec();
    let plaintext = cx.argument::<JsArrayBuffer>(2)?.as_slice(&cx).to_vec();
    let aad = cx.argument::<JsArrayBuffer>(3)?.as_slice(&cx).to_vec();

    let gc = group_crypto::DTGroupCrypto::new(version);
    let blob = gc.encrypt(k_group, plaintext, aad)
        .or_else(|e| { throw_proto_error(&mut cx, e)?; unreachable!() })?;

    vec_to_buffer(&mut cx, &blob)
}

pub fn neon_group_crypto_decrypt(mut cx: FunctionContext) -> JsResult<JsArrayBuffer> {
    let version = cx.argument::<JsNumber>(0)?.value(&mut cx) as u8;
    let k_group = cx.argument::<JsArrayBuffer>(1)?.as_slice(&cx).to_vec();
    let blob = cx.argument::<JsArrayBuffer>(2)?.as_slice(&cx).to_vec();
    let aad = cx.argument::<JsArrayBuffer>(3)?.as_slice(&cx).to_vec();

    let gc = group_crypto::DTGroupCrypto::new(version);
    let plaintext = gc.decrypt(k_group, blob, aad)
        .or_else(|e| { throw_proto_error(&mut cx, e)?; unreachable!() })?;

    vec_to_buffer(&mut cx, &plaintext)
}

pub fn neon_group_crypto_sign_uid(mut cx: FunctionContext) -> JsResult<JsArrayBuffer> {
    let version = cx.argument::<JsNumber>(0)?.value(&mut cx) as u8;
    let sk_bind = cx.argument::<JsArrayBuffer>(1)?.as_slice(&cx).to_vec();
    let uid = cx.argument::<JsString>(2)?.value(&mut cx);

    let gc = group_crypto::DTGroupCrypto::new(version);
    let signature = gc.sign_uid(sk_bind, uid)
        .or_else(|e| { throw_proto_error(&mut cx, e)?; unreachable!() })?;

    vec_to_buffer(&mut cx, &signature)
}

pub fn neon_group_crypto_verify_uid(mut cx: FunctionContext) -> JsResult<JsBoolean> {
    let version = cx.argument::<JsNumber>(0)?.value(&mut cx) as u8;
    let pk_bind = cx.argument::<JsArrayBuffer>(1)?.as_slice(&cx).to_vec();
    let uid = cx.argument::<JsString>(2)?.value(&mut cx);
    let signature = cx.argument::<JsArrayBuffer>(3)?.as_slice(&cx).to_vec();

    let gc = group_crypto::DTGroupCrypto::new(version);
    let valid = gc.verify_uid(pk_bind, uid, signature)
        .or_else(|e| { throw_proto_error(&mut cx, e)?; unreachable!() })?;

    Ok(cx.boolean(valid))
}

pub fn decrypt_rtm_message(mut cx: FunctionContext) -> JsResult<JsObject> {
    let version = cx.argument::<JsNumber>(0)?.value(&mut cx);
    let signature = cx.argument::<JsArrayBuffer>(1)?.as_slice(&cx).to_vec();
    let their_id_key_value = cx.argument::<JsArrayBuffer>(2)?.as_slice(&cx).to_vec();
    let their_local_id_key: Option<Vec<u8>>;
    if their_id_key_value.is_empty(){
        their_local_id_key = None;
    } else {
        their_local_id_key = Some(their_id_key_value);
    }
    let aes_key = cx.argument::<JsArrayBuffer>(3)?.as_slice(&cx).to_vec();
    let cipher_text = cx.argument::<JsArrayBuffer>(4)?.as_slice(&cx).to_vec();
    let proto = DTProto{version: version as i32};
    let decrypted_message_or_error = proto.decrypt_rtm_message(signature, their_local_id_key, aes_key, cipher_text);
    let decrypted_message = decrypted_message_or_error.or_else(|e| {
        let err = JsError::error(&mut cx, e.to_string())?;
        let code = cx.number(e as i32);
        err.set(&mut cx, "code", code)?;
        cx.throw(err)?;
        unreachable!()
    })?;

    let result = cx.empty_object();
    let mut plain_text = cx.array_buffer(decrypted_message.plain_text.len())?;
    for (i, elem) in plain_text.as_mut_slice(&mut cx).iter_mut().enumerate() {
        *elem = decrypted_message.plain_text[i];
    }
    let verified_id_result = cx.boolean(decrypted_message.verified_id_result);
    result.set(&mut cx, "plain_text", plain_text)?;
    result.set(&mut cx, "verified_id_result", verified_id_result)?;
    Ok(result)
}