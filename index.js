const v = require("node-bindgen-loader")({
  moduleName: "ssb-validate2-rsjs-node",
  dir: __dirname,
});

const stringify = (msg) => JSON.stringify(msg, null, 2);

const verifySignatures = (hmacKey, msgs, cb) => {
  if (!Array.isArray(msgs)) {
    cb(new Error("input must be an array of message objects"));
    return;
  }
  const jsonMsgs = msgs.map(stringify);
  // convert `null` and `undefined` to a string ("none") for easier matching in rustland
  if (!hmacKey) hmacKey = "none";
  const [err, result] = v.verifySignatures(hmacKey, jsonMsgs);
  if (err) {
    cb(new Error(err));
    return;
  }
  cb(err, result);
};

const validateSingle = (hmacKey, msg, previous, cb) => {
  const jsonMsg = stringify(msg);
  // convert `null` and `undefined` to a string ("none") for easier matching in rustland
  if (!hmacKey) hmacKey = "none";
  let err;
  let result;
  if (previous) {
    const jsonPrevious = stringify(previous);
    // `result` is a string of the hash (`key`) for the given `jsonMsg` value
    [err, result] = v.validateSingle(hmacKey, jsonMsg, jsonPrevious);
  } else {
    [err, result] = v.validateSingle(hmacKey, jsonMsg);
  }
  if (err) {
    cb(new Error(err));
    return;
  }
  cb(err, result);
};

const validateBatch = (hmacKey, msgs, previous, cb) => {
  if (!Array.isArray(msgs)) {
    cb(new Error("input must be an array of message objects"));
    return;
  }
  const jsonMsgs = msgs.map(stringify);
  if (!hmacKey) hmacKey = "none";
  let err;
  let result;
  if (previous) {
    const jsonPrevious = stringify(previous);
    // `result` is an array of strings (each string a `key`) for the given `jsonMsgs`
    [err, result] = v.validateBatch(hmacKey, jsonMsgs, jsonPrevious);
  } else {
    [err, result] = v.validateBatch(hmacKey, jsonMsgs);
  }
  if (err) {
    cb(new Error(err));
    return;
  }
  cb(err, result);
};

const validateOOOBatch = (hmacKey, msgs, cb) => {
  if (!Array.isArray(msgs)) {
    cb(new Error("input must be an array of message objects"));
    return;
  }
  const jsonMsgs = msgs.map(stringify);
  if (!hmacKey) hmacKey = "none";
  const [err, result] = v.validateOOOBatch(hmacKey, jsonMsgs);
  if (err) {
    cb(new Error(err));
    return;
  }
  cb(err, result);
};

const validateMultiAuthorBatch = (hmacKey, msgs, cb) => {
  if (!Array.isArray(msgs)) {
    cb(new Error("input must be an array of message objects"));
    return;
  }
  const jsonMsgs = msgs.map(stringify);
  if (!hmacKey) hmacKey = "none";
  const [err, result] = v.validateMultiAuthorBatch(hmacKey, jsonMsgs);
  if (err) {
    cb(new Error(err));
    return;
  }
  cb(err, result);
};

// Mirrors the `ready` function for the `web` version of `ssb-validate2-rsjs`.
// The function initializes WASM and WebWorkers in `web`. We define it here with
// a callback so that both libraries can be safely called with the same code.
const ready = (cb) => {
  cb();
};

module.exports.ready = ready;
module.exports.verifySignatures = verifySignatures;
module.exports.validateSingle = validateSingle;
module.exports.validateBatch = validateBatch;
module.exports.validateOOOBatch = validateOOOBatch;
module.exports.validateMultiAuthorBatch = validateMultiAuthorBatch;
