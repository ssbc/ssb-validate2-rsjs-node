const v = require('node-bindgen-loader')({
  moduleName: 'ssb-validate2-rsjs-node',
  dir: __dirname
})

const stringify = (msg) => JSON.stringify(msg, null, 2)

const verifySignatures = (msgs, cb) => {
  if (!Array.isArray(msgs)) return "input must be an array of message objects";
  const jsonMsgs = msgs.map(stringify);
  const [err, result] = v.verifySignatures(jsonMsgs);
  cb(err, result);
};

const validateSingle = (msg, previous, cb) => {
  const jsonMsg = stringify(msg);
  if (previous) {
    const jsonPrevious = stringify(previous);
    // `result` is a string of the hash (`key`) for the given `jsonMsg` value
    const [err, result] = v.validateSingle(jsonMsg, jsonPrevious);
    cb(err, result);
  } else {
    const [err, result] = v.validateSingle(jsonMsg);
    cb(err, result);
  }
};

const validateBatch = (msgs, previous, cb) => {
  if (!Array.isArray(msgs)) return "input must be an array of message objects";
  const jsonMsgs = msgs.map(stringify);
  if (previous) {
    const jsonPrevious = stringify(previous);
    // `result` is an array of strings (each string a `key`) for the given `jsonMsgs`
    const [err, result] = v.validateBatch(jsonMsgs, jsonPrevious);
    cb(err, result);
  } else {
    const [err, result] = v.validateBatch(jsonMsgs);
    cb(err, result);
  }
};

const validateOOOBatch = (msgs, cb) => {
  if (!Array.isArray(msgs)) return "input must be an array of message objects";
  const jsonMsgs = msgs.map(stringify);
  const [err, result] = v.validateOOOBatch(jsonMsgs);
  cb(err, result);
};

const validateMultiAuthorBatch = (msgs, cb) => {
  if (!Array.isArray(msgs))
    throw new Error("input must be an array of message objects");
  const jsonMsgs = msgs.map(stringify);
  const [err, result] = v.validateMultiAuthorBatch(jsonMsgs);
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
