// SPDX-FileCopyrightText: 2021 Andrew 'glyph' Reid
//
// SPDX-License-Identifier: LGPL-3.0-only

use node_bindgen::core::{buffer::JSArrayBuffer, val::JsEnv, JSValue, NjError};
use node_bindgen::derive::node_bindgen;
use node_bindgen::sys::napi_value;
use ssb_crypto::{AsBytes, NetworkKey as MsgHmacKey};
use ssb_validate::{
    message_value::{
        par_validate_message_value, par_validate_message_value_hash_chain_of_feed,
        par_validate_ooo_message_value_hash_chain_of_feed, validate_message_value,
        validate_message_value_hash_chain, validate_ooo_message_value_hash_chain,
    },
    utils,
};
use ssb_verify_signatures::{par_verify_message_values, verify_message_value};

// custom `enum` to allow type conversion of the message-signing hmac from js
enum HmacKey {
    Buf(JSArrayBuffer),
    Str(String),
}

// implement type conversion for our custom `HmacKey` enum
// we're primarily interested in strings and array buffers
impl JSValue<'_> for HmacKey {
    fn convert_to_rust(env: &JsEnv, n_value: napi_value) -> Result<Self, NjError> {
        if let Ok(string_value) = env.convert_to_rust::<String>(n_value) {
            Ok(Self::Str(string_value))
        } else if let Ok(buffer_value) = env.convert_to_rust::<JSArrayBuffer>(n_value) {
            Ok(Self::Buf(buffer_value))
        } else {
            Err(NjError::Other(
                "hmacKey must be of type string, array buffer, null or undefined".to_owned(),
            ))
        }
    }
}

// The HMAC we are dealing with here is the 'message-signing HMAC' and not the 'network HMAC'
// which is used during the secret-handshake between peers (aka network identifier, app key
// or caps key). While both use the same hashing algorithms (`HMAC-SHA-512-256`), they are
// employed in different ways. Message signing with an HMAC is an optional feature of
// Scuttlebutt and is not put to use in the main network. This is why a `null` or `None`
// value is set for the message-signing HMAC when verifying main network message signatures.
//
// the `Ok()` variant for `Result` represents a valid hmac key value as a byte vector
fn is_valid_hmac_key(hmac_key: HmacKey) -> Result<Option<Vec<u8>>, String> {
    match hmac_key {
        HmacKey::Buf(hmac) => {
            let key = MsgHmacKey::from_slice(&hmac);
            match key {
                None => Err("hmac key invalid: byte length must equal 32".to_string()),
                Some(key_val) => {
                    let key_bytes = key_val.as_bytes().to_vec();
                    Ok(Some(key_bytes))
                }
            }
        }
        HmacKey::Str(hmac) => {
            let key = MsgHmacKey::from_base64(&hmac);
            // match on what would have been `null` or `undefined` for `hmacKey`
            // in the js function call. these values are considered valid.
            if hmac == "none" {
                Ok(None)
            } else {
                match key {
                    None => Err("hmac key invalid: string must be base64 encoded".to_string()),
                    Some(key_val) => {
                        let key_bytes = key_val.as_bytes().to_vec();
                        Ok(Some(key_bytes))
                    }
                }
            }
        }
    }
}

fn hash(msgs: Vec<Vec<u8>>) -> Vec<String> {
    let mut keys = Vec::new();
    for msg in msgs {
        let multihash = utils::multihash_from_bytes(&msg);
        let key = multihash.to_legacy_string();
        keys.push(key);
    }
    keys
}

/// Verify signatures for an array of messages (includes HMAC key support).
///
/// Takes an HMAC key as the first argument and an array of messages as the second argument.
/// The HMAC key must be of type `string` or `ArrayBuffer`. Message signatures are verified without
/// an HMAC key if the value of the argument is a `string` with value `none`.
///
/// If verification fails, the cause of the error is returned along with the offending message.
/// Note: this method only verifies message signatures; it does not perform full message validation
/// (use `verify_validate_message_array` for complete verification and validation).
#[node_bindgen(name = "verifySignatures")]
fn verify_messages(hmac_key: HmacKey, array: Vec<String>) -> (Option<String>, Option<Vec<String>>) {
    let valid_hmac = match is_valid_hmac_key(hmac_key) {
        Ok(key) => key,
        Err(err_msg) => return (Some(err_msg), None),
    };
    let hmac = valid_hmac.as_deref();

    let mut msgs = Vec::new();
    for msg in array {
        let msg_bytes = msg.into_bytes();
        msgs.push(msg_bytes)
    }

    // attempt batch verification and match on error to find invalid message value
    match par_verify_message_values(&msgs, hmac, None) {
        Ok(_) => (),
        Err(e) => {
            let invalid_msg = &msgs
                .iter()
                .find(|msg| verify_message_value(msg, hmac).is_err());
            let invalid_msg_str = match invalid_msg {
                Some(msg) => std::str::from_utf8(msg).unwrap_or(
                    "unable to convert invalid message bytes to string slice; not valid utf8",
                ),
                None => "parallel verification failed but no single invalid message was found",
            };
            let err_msg = format!("found invalid message: {}: {}", e, invalid_msg_str);
            return (Some(err_msg), None);
        }
    }

    let keys = hash(msgs);
    (None, Some(keys))
}

/// Verify signature and perform validation for a single message value (includes HMAC key support).
///
/// Takes an HMAC key as the first argument, message `value` as the second argument and an optional
/// previous message `value` as the third argument. The HMAC key must be of type `string` or
/// `ArrayBuffer`. Message signatures are verified without an HMAC key if the value of the argument
/// is a `string` with value `none`. The previous message argument is expected when the message to
/// be validated is not the first in the feed (ie. sequence number != 1 and previous != null).
///
/// The return type is a tuple of `Option<String>`. The first element of the tuple holds the key
/// (hash) of `msg_value` (if validation is successful) while the second element holds the error
/// messages (if validation fails). Only the key for `msg_value` is returned; the key for `previous`
/// is not.
///
/// Successful validation will yield a return value of `(Some<key>, None)` - where `key` is of type
/// `String`. Unsuccessful validation will yield a return value of `(None, Some<err_msg>)` - where
/// `err_msg` is of type `String` and includes the cause of the error and the offending message.
#[node_bindgen(name = "validateSingle")]
fn verify_validate_message(
    hmac_key: HmacKey,
    msg_value: String,
    previous: Option<String>,
) -> (Option<String>, Option<String>) {
    let valid_hmac = match is_valid_hmac_key(hmac_key) {
        Ok(key) => key,
        Err(err_msg) => return (Some(err_msg), None),
    };
    let hmac = valid_hmac.as_deref();

    let msg_bytes = msg_value.into_bytes();
    let previous_msg_bytes = previous.map(|msg| msg.into_bytes());

    // attempt verification and match on error to find invalid message
    match verify_message_value(&msg_bytes, hmac) {
        Ok(_) => (),
        Err(e) => {
            let invalid_msg_str = std::str::from_utf8(&msg_bytes).unwrap_or(
                "unable to convert invalid message bytes to string slice; not valid utf8",
            );
            let err_msg = format!("found invalid message: {}: {}", e, invalid_msg_str);
            return (Some(err_msg), None);
        }
    };

    // attempt validation and match on error to find invalid message
    match validate_message_value_hash_chain(&msg_bytes, previous_msg_bytes) {
        Ok(_) => (),
        Err(e) => {
            let invalid_msg_str = std::str::from_utf8(&msg_bytes).unwrap_or(
                "unable to convert invalid message bytes to string slice; not valid utf8",
            );
            let err_msg = format!("found invalid message: {}: {}", e, invalid_msg_str);
            return (Some(err_msg), None);
        }
    };

    // generate multihash from message value bytes
    let multihash = utils::multihash_from_bytes(&msg_bytes);
    let key = multihash.to_legacy_string();
    (None, Some(key))
}

/// Verify signatures and perform validation for an array of ordered message values by a single
/// author (includes HMAC key support).
///
/// Takes an HMAC key as the first argument, an array of message values as the second argument
/// and an optional previous message value as the third argument. The HMAC key must be of type
/// `string` or `ArrayBuffer`. Message signatures are verified without an HMAC key if the value
/// of the argument is a `string` with value `none`. The previous message argument is expected
/// when the array of messages does not start from the beginning of the feed (ie. sequence number
/// != 1 and previous != null). If verification or validation fails, the cause of the error is
/// returned along with the offending message.
#[node_bindgen(name = "validateBatch")]
fn verify_validate_messages(
    hmac_key: HmacKey,
    array: Vec<String>,
    previous: Option<String>,
) -> (Option<String>, Option<Vec<String>>) {
    let valid_hmac = match is_valid_hmac_key(hmac_key) {
        Ok(key) => key,
        Err(err_msg) => return (Some(err_msg), None),
    };
    let hmac = valid_hmac.as_deref();

    let mut msgs = Vec::new();
    for msg in array {
        let msg_bytes = msg.into_bytes();
        msgs.push(msg_bytes)
    }

    let previous_msg = previous.map(|msg| msg.into_bytes());

    // attempt batch verification and match on error to find invalid message value
    match par_verify_message_values(&msgs, hmac, None) {
        Ok(_) => (),
        Err(e) => {
            let invalid_msg = &msgs
                .iter()
                .find(|msg| verify_message_value(msg, hmac).is_err());
            let invalid_msg_str = match invalid_msg {
                Some(msg) => std::str::from_utf8(msg).unwrap_or(
                    "unable to convert invalid message bytes to string slice; not valid utf8",
                ),
                None => "parallel verification failed but no single invalid message was found",
            };
            let err_msg = format!("found invalid message: {}: {}", e, invalid_msg_str);
            return (Some(err_msg), None);
        }
    };

    // attempt batch validation and match on error to find invalid message value
    match par_validate_message_value_hash_chain_of_feed(&msgs, previous_msg.as_ref()) {
        Ok(_) => (),
        Err(e) => {
            let invalid_msg = &msgs
                .iter()
                .find(|msg| validate_message_value_hash_chain(msg, previous_msg.as_ref()).is_err());
            let invalid_msg_str = match invalid_msg {
                Some(msg) => std::str::from_utf8(msg).unwrap_or(
                    "unable to convert invalid message bytes to string slice; not valid utf8",
                ),
                None => "parallel validation failed but no single invalid message was found",
            };
            let err_msg = format!("found invalid message: {}: {}", e, invalid_msg_str);
            return (Some(err_msg), None);
        }
    }

    let keys = hash(msgs);
    (None, Some(keys))
}

/// Verify signatures and perform validation for an array of out-of-order messages by a single
/// author (includes HMAC key support).
///
/// Takes an HMAC key as the first argument and an array of messages as the second argument.
/// The HMAC key must be of type `string` or `ArrayBuffer`. Message signatures are verified
/// without an HMAC key if the value of the argument is a `string` with value `none`. If
/// verification or validation fails, the cause of the error is returned along with the
/// offending message.
#[node_bindgen(name = "validateOOOBatch")]
fn verify_validate_out_of_order_messages(
    hmac_key: HmacKey,
    array: Vec<String>,
) -> (Option<String>, Option<Vec<String>>) {
    let valid_hmac = match is_valid_hmac_key(hmac_key) {
        Ok(key) => key,
        Err(err_msg) => return (Some(err_msg), None),
    };
    let hmac = valid_hmac.as_deref();

    let mut msgs = Vec::new();
    for msg in array {
        let msg_bytes = msg.into_bytes();
        msgs.push(msg_bytes)
    }

    // attempt batch verification and match on error to find invalid message value
    match par_verify_message_values(&msgs, hmac, None) {
        Ok(_) => (),
        Err(e) => {
            let invalid_msg = &msgs
                .iter()
                .find(|msg| verify_message_value(msg, hmac).is_err());
            let invalid_msg_str = match invalid_msg {
                Some(msg) => std::str::from_utf8(msg).unwrap_or(
                    "unable to convert invalid message bytes to string slice; not valid utf8",
                ),
                None => "parallel verification failed but no single invalid message was found",
            };
            let err_msg = format!("found invalid message: {}: {}", e, invalid_msg_str);
            return (Some(err_msg), None);
        }
    };

    // attempt batch validation and match on error to find invalid message
    match par_validate_ooo_message_value_hash_chain_of_feed::<_, &[u8]>(&msgs, None) {
        Ok(_) => (),
        Err(e) => {
            let invalid_msg = &msgs
                .iter()
                .find(|msg| validate_ooo_message_value_hash_chain::<_, &[u8]>(msg, None).is_err());
            let invalid_msg_str = match invalid_msg {
                Some(msg) => std::str::from_utf8(msg).unwrap_or(
                    "unable to convert invalid message bytes to string slice; not valid utf8",
                ),
                None => "parallel validation failed but no single invalid message was found",
            };
            let err_msg = format!("found invalid message: {}: {}", e, invalid_msg_str);
            return (Some(err_msg), None);
        }
    }

    let keys = hash(msgs);
    (None, Some(keys))
}

/// Verify signatures and perform validation for an array of out-of-order messages by multiple
/// authors (includes HMAC key support).
///
/// Takes an HMAC key as the first argument and an array of messages as the second argument. The
/// HMAC key must be of type `string` or `ArrayBuffer`. Message signatures are verified without
/// an HMAC key if the value of the argument is a `string` with value `none`. If  verification
/// or validation fails, the cause of the error is returned along with the offending message.
#[node_bindgen(name = "validateMultiAuthorBatch")]
fn verify_validate_multi_author_messages(
    hmac_key: HmacKey,
    array: Vec<String>,
) -> (Option<String>, Option<Vec<String>>) {
    let valid_hmac = match is_valid_hmac_key(hmac_key) {
        Ok(key) => key,
        Err(err_msg) => return (Some(err_msg), None),
    };
    let hmac = valid_hmac.as_deref();

    let mut msgs = Vec::new();
    for msg in array {
        let msg_bytes = msg.into_bytes();
        msgs.push(msg_bytes)
    }

    // attempt batch verification and match on error to find invalid message value
    match par_verify_message_values(&msgs, hmac, None) {
        Ok(_) => (),
        Err(e) => {
            let invalid_msg = &msgs
                .iter()
                .find(|msg| verify_message_value(msg, hmac).is_err());
            let invalid_msg_str = match invalid_msg {
                Some(msg) => std::str::from_utf8(msg).unwrap_or(
                    "unable to convert invalid message bytes to string slice; not valid utf8",
                ),
                None => "parallel verification failed but no single invalid message was found",
            };
            let err_msg = format!("found invalid message: {}: {}", e, invalid_msg_str);
            return (Some(err_msg), None);
        }
    };

    // attempt batch validation and match on error to find invalid message
    match par_validate_message_value(&msgs) {
        Ok(_) => (),
        Err(e) => {
            let invalid_msg = &msgs.iter().find(|msg| validate_message_value(msg).is_err());
            let invalid_msg_str = match invalid_msg {
                Some(msg) => std::str::from_utf8(msg).unwrap_or(
                    "unable to convert invalid message bytes to string slice; not valid utf8",
                ),
                None => "parallel validation failed but no single invalid message was found",
            };
            let err_msg = format!("found invalid message: {}: {}", e, invalid_msg_str);
            return (Some(err_msg), None);
        }
    }

    let keys = hash(msgs);
    (None, Some(keys))
}
