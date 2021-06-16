// SPDX-License-Identifier: AGPL-3.0-only

use node_bindgen::derive::node_bindgen;
use ssb_validate::{
    message_value::{
        par_validate_message_value, par_validate_message_value_hash_chain_of_feed,
        par_validate_ooo_message_value_hash_chain_of_feed, validate_message_value,
        validate_message_value_hash_chain, validate_ooo_message_value_hash_chain,
    },
    utils,
};
use ssb_verify_signatures::{par_verify_message_values, verify_message_value};

fn hash(msgs: Vec<Vec<u8>>) -> Vec<String> {
    let mut keys = Vec::new();
    for msg in msgs {
        let multihash = utils::multihash_from_bytes(&msg);
        let key = multihash.to_legacy_string();
        keys.push(key);
    }
    keys
}

/// Verify signatures for an array of messages.
///
/// Takes an array of messages as the only argument. If verification fails, the cause of the error
/// is returned along with the offending message. Note: this method only verifies message signatures;
/// it does not perform full message validation (use `verify_validate_message_array` for complete
/// verification and validation).
#[node_bindgen(name = "verifySignatures")]
fn verify_messages(array: Vec<String>) -> (Option<String>, Option<Vec<String>>) {
    let mut msgs = Vec::new();
    for msg in array {
        let msg_bytes = msg.into_bytes();
        msgs.push(msg_bytes)
    }

    // attempt batch verification and match on error to find invalid message
    match par_verify_message_values(&msgs, None) {
        Ok(_) => (),
        Err(e) => {
            let invalid_msg = &msgs
                .iter()
                .find(|msg| verify_message_value(msg).is_err())
                .unwrap();
            let invalid_msg_str = std::str::from_utf8(invalid_msg).unwrap();
            let err_msg = format!("found invalid message: {}: {}", e, invalid_msg_str);
            return (Some(err_msg), None);
        }
    }

    let keys = hash(msgs);
    (None, Some(keys))
}

/// Verify signature and perform validation for a single message value.
///
/// Takes a message `value` as the first argument and an optional previous message `value` as the second
/// argument. The previous message argument is expected when the message to be validated is not the
/// first in the feed (ie. sequence number != 1 and previous != null).
///
/// The return type is a tuple of `Option<String>`. The first element of the tuple holds the key
/// (hash) of `msg_value`
/// (if validation is successful) while the second element holds the error messages (if validation fails). Only the key for `msg_value` is returned; the key for `previous` is not.
/// Successful validation will yield a return value of `(Some<key>, None)` - where `key` is of type
/// `String`.
/// Unsuccessful validation will yield a return value of `(None, Some<err_msg>)` - where `err_msg`
/// is of type `String` and includes the cause of the error and the offending
/// message.
#[node_bindgen(name = "validateSingle")]
fn verify_validate_message(
    msg_value: String,
    previous: Option<String>,
) -> (Option<String>, Option<String>) {
    let msg_bytes = msg_value.into_bytes();
    let previous_msg_bytes = previous.map(|msg| msg.into_bytes());

    // attempt verification and match on error to find invalid message
    match verify_message_value(&msg_bytes) {
        Ok(_) => (),
        Err(e) => {
            let invalid_msg_str = std::str::from_utf8(&msg_bytes).unwrap();
            let err_msg = format!("found invalid message: {}: {}", e, invalid_msg_str);
            return (Some(err_msg), None);
        }
    };

    // attempt validation and match on error to find invalid message
    match validate_message_value_hash_chain(&msg_bytes, previous_msg_bytes) {
        Ok(_) => (),
        Err(e) => {
            let invalid_msg_str = std::str::from_utf8(&msg_bytes).unwrap();
            let err_msg = format!("found invalid message: {}: {}", e, invalid_msg_str);
            return (Some(err_msg), None);
        }
    };

    // generate multihash from message value bytes
    let multihash = utils::multihash_from_bytes(&msg_bytes);
    let key = multihash.to_legacy_string();
    (None, Some(key))
}

/// Verify signatures and perform validation for an array of ordered message values by a single author.
///
/// Takes an array of message values as the first argument and an optional previous message value as the second
/// argument. The previous message argument is expected when the array of messages does not start
/// from the beginning of the feed (ie. sequence number != 1 and previous != null). If
/// verification or validation fails, the cause of the error is returned along with the offending
/// message.
#[node_bindgen(name = "validateBatch")]
fn verify_validate_messages(
    array: Vec<String>,
    previous: Option<String>,
) -> (Option<String>, Option<Vec<String>>) {
    let mut msgs = Vec::new();
    for msg in array {
        let msg_bytes = msg.into_bytes();
        msgs.push(msg_bytes)
    }

    let previous_msg = previous.map(|msg| msg.into_bytes());

    // attempt batch verification and match on error to find invalid message value
    match par_verify_message_values(&msgs, None) {
        Ok(_) => (),
        Err(e) => {
            let invalid_msg = &msgs
                .iter()
                .find(|msg| verify_message_value(msg).is_err())
                .unwrap();
            let invalid_msg_str = std::str::from_utf8(invalid_msg).unwrap();
            let err_msg = format!("found invalid message: {}: {}", e, invalid_msg_str);
            return (Some(err_msg), None);
        }
    };

    // attempt batch validation and match on error to find invalid message value
    match par_validate_message_value_hash_chain_of_feed(&msgs, previous_msg.as_ref()) {
        Ok(_) => (),
        Err(e) => {
            let invalid_message = &msgs
                .iter()
                .find(|msg| validate_message_value_hash_chain(msg, previous_msg.as_ref()).is_err())
                .unwrap();
            let invalid_msg_str = std::str::from_utf8(invalid_message).unwrap();
            let err_msg = format!("found invalid message: {}: {}", e, invalid_msg_str);
            return (Some(err_msg), None);
        }
    }

    let keys = hash(msgs);
    (None, Some(keys))
}

/// Verify signatures and perform validation for an array of out-of-order messages by a single
/// author.
///
/// Takes an array of messages as the only argument. If verification or validation fails, the
/// cause of the error is returned along with the offending message.
#[node_bindgen(name = "validateOOOBatch")]
fn verify_validate_out_of_order_messages(
    array: Vec<String>,
) -> (Option<String>, Option<Vec<String>>) {
    let mut msgs = Vec::new();
    for msg in array {
        let msg_bytes = msg.into_bytes();
        msgs.push(msg_bytes)
    }

    // attempt batch verification and match on error to find invalid message
    match par_verify_message_values(&msgs, None) {
        Ok(_) => (),
        Err(e) => {
            let invalid_msg = &msgs
                .iter()
                .find(|msg| verify_message_value(msg).is_err())
                .unwrap();
            let invalid_msg_str = std::str::from_utf8(invalid_msg).unwrap();
            let err_msg = format!("found invalid message: {}: {}", e, invalid_msg_str);
            return (Some(err_msg), None);
        }
    };

    // attempt batch validation and match on error to find invalid message
    match par_validate_ooo_message_value_hash_chain_of_feed::<_, &[u8]>(&msgs, None) {
        Ok(_) => (),
        Err(e) => {
            let invalid_message = &msgs
                .iter()
                .find(|msg| validate_ooo_message_value_hash_chain::<_, &[u8]>(msg, None).is_err())
                .unwrap();
            let invalid_msg_str = std::str::from_utf8(invalid_message).unwrap();
            let err_msg = format!("found invalid message: {}: {}", e, invalid_msg_str);
            return (Some(err_msg), None);
        }
    }

    let keys = hash(msgs);
    (None, Some(keys))
}

/// Verify signatures and perform validation for an array of out-of-order messages by multiple
/// authors.
///
/// Takes an array of messages as the only argument. If verification or validation fails, the
/// cause of the error is returned along with the offending message.
#[node_bindgen(name = "validateMultiAuthorBatch")]
fn verify_validate_multi_author_messages(
    array: Vec<String>,
) -> (Option<String>, Option<Vec<String>>) {
    let mut msgs = Vec::new();
    for msg in array {
        let msg_bytes = msg.into_bytes();
        msgs.push(msg_bytes)
    }

    // attempt batch verification and match on error to find invalid message
    match par_verify_message_values(&msgs, None) {
        Ok(_) => (),
        Err(e) => {
            let invalid_msg = &msgs
                .iter()
                .find(|msg| verify_message_value(msg).is_err())
                .unwrap();
            let invalid_msg_str = std::str::from_utf8(invalid_msg).unwrap();
            let err_msg = format!("found invalid message: {}: {}", e, invalid_msg_str);
            return (Some(err_msg), None);
        }
    };

    // attempt batch validation and match on error to find invalid message
    match par_validate_message_value(&msgs) {
        Ok(_) => (),
        Err(e) => {
            let invalid_message = &msgs
                .iter()
                .find(|msg| validate_message_value(msg).is_err())
                .unwrap();
            let invalid_msg_str = std::str::from_utf8(invalid_message).unwrap();
            let err_msg = format!("found invalid message: {}: {}", e, invalid_msg_str);
            return (Some(err_msg), None);
        }
    }

    let keys = hash(msgs);
    (None, Some(keys))
}
