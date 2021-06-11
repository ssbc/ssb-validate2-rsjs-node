const v = require('node-bindgen-loader')({
  moduleName: 'ssb-validate2-rsjs-node',
  dir: __dirname
})

const stringify = (msg) => JSON.stringify(msg, null, 2)

const verifySignatures = (msgs, cb) => {
  if (!Array.isArray(msgs)) return "input must be an array of message objects";
  const jsonMsgs = msgs.map(stringify);
  cb(v.verifySignatures(jsonMsgs));
};

const validateSingle = (msg, previous, cb) => {
  const jsonMsg = stringify(msg);
  if (previous) {
    const jsonPrevious = stringify(previous);
    cb(v.validateSingle(jsonMsg, jsonPrevious));
  } else {
    cb(v.validateSingle(jsonMsg));
  }
};

const validateBatch = (msgs, previous, cb) => {
  if (!Array.isArray(msgs)) return "input must be an array of message objects";
  const jsonMsgs = msgs.map(stringify);
  if (previous) {
    const jsonPrevious = stringify(previous);
    cb(v.validateBatch(jsonMsgs, jsonPrevious));
  } else {
    cb(v.validateBatch(jsonMsgs));
  }
};

const validateOOOBatch = (msgs, cb) => {
  if (!Array.isArray(msgs)) return "input must be an array of message objects";
  const jsonMsgs = msgs.map(stringify);
  cb(v.validateOOOBatch(jsonMsgs));
};

const validateMultiAuthorBatch = (msgs, cb) => {
  if (!Array.isArray(msgs))
    throw new Error("input must be an array of message objects");
  const jsonMsgs = msgs.map(stringify);
  cb(v.validateMultiAuthorBatch(jsonMsgs));
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
