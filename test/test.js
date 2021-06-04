const validate = require("../");
const test = require("tape");
const fs = require("fs");
const path = require("path");
const Log = require("async-append-only-log");
const generateFixture = require("ssb-fixtures");
const rimraf = require("rimraf");
const mkdirp = require("mkdirp");
const JITDB = require("jitdb");
const {
  query,
  fromDB,
  where,
  equal,
  slowEqual,
  toCallback,
} = require("jitdb/operators");
const seekType = require("jitdb/test/helpers");
const copy = require("jitdb/copy-json-to-bipf-async");

// define directory and paths
const dir = "/tmp/validate-test";
const oldLogPath = path.join(dir, "flume", "log.offset");
const newLogPath = path.join(dir, "flume", "log.bipf");
const indexesDir = path.join(dir, "indexes");

// generate fixture
rimraf.sync(dir, { maxBusyTries: 3 });
mkdirp.sync(dir);

const SEED = "sloop";
const MESSAGES = 5;
const AUTHORS = 1;

const validMsg = {
  key: "%kmXb3MXtBJaNugcEL/Q7G40DgcAkMNTj3yhmxKHjfCM=.sha256",
  value: {
    previous: "%IIjwbJbV3WBE/SBLnXEv5XM3Pr+PnMkrAJ8F+7TsUVQ=.sha256",
    author: "@U5GvOKP/YUza9k53DSXxT0mk3PIrnyAmessvNfZl5E0=.ed25519",
    sequence: 8,
    timestamp: 1470187438539,
    hash: "sha256",
    content: {
      type: "contact",
      contact: "@ye+QM09iPcDJD6YvQYjoQc7sLF/IFhmNbEqgdzQo3lQ=.ed25519",
      following: true,
      blocking: false,
    },
    signature:
      "PkZ34BRVSmGG51vMXo4GvaoS/2NBc0lzdFoVv4wkI8E8zXv4QYyE5o2mPACKOcrhrLJpymLzqpoE70q78INuBg==.sig.ed25519",
  },
  timestamp: 1571140551543,
};

test("generate fixture with flumelog-offset", (t) => {
  generateFixture({
    outputDir: dir,
    seed: SEED,
    messages: MESSAGES,
    authors: AUTHORS,
    slim: false,
  }).then(() => {
    t.true(fs.existsSync(oldLogPath), "log.offset was created");
    t.end();
  });
});

test("move flumelog-offset to async-log", (t) => {
  copy(oldLogPath, newLogPath, (err) => {
    if (err) t.fail(err);
    setTimeout(() => {
      t.true(fs.existsSync(newLogPath), "log.bipf was created");
      t.end();
    }, 4000);
  });
});

let raf;
let db;

test("core indexes", (t) => {
  raf = Log(newLogPath, { blockSize: 64 * 1024 });
  rimraf.sync(indexesDir);
  db = JITDB(raf, indexesDir);
  db.onReady(() => {
    t.pass(`database ready`);
    t.end();
  });
});

test("batch verification of message signatures", (t) => {
  db.onReady(() => {
    query(
      fromDB(db),
      toCallback((err, msgs) => {
        if (err) t.fail(err);
        // attempt verification of all messages
        t.equal(validate.verifySignatures(msgs), null, "success");
        t.pass(`validated ${MESSAGES} messages`);
        t.end();
      })
    );
  });
});

test("batch verification of out-of-order message signatures", (t) => {
  db.onReady(() => {
    query(
      fromDB(db),
      toCallback((err, msgs) => {
        if (err) t.fail(err);
        // shuffle the messages (generate out-of-order state)
        msgs.sort(() => Math.random() - 0.5);
        // attempt verification of all messages
        t.equal(validate.verifySignatures(msgs), null, "success");
        t.pass(`validated ${MESSAGES} messages`);
        t.end();
      })
    );
  });
});

test("verification of single message signature (valid)", (t) => {
  let msgs = [validMsg];
  t.equal(validate.verifySignatures(msgs), null, "success");
  t.pass(`validated ${MESSAGES} messages`);
  t.end();
});

test("verification of single message signature (invalid)", (t) => {
  let invalidMsg = validMsg;
  invalidMsg.value.content.following = false;
  let msgs = [invalidMsg];
  t.match(
    validate.verifySignatures(msgs),
    /Signature was invalid/,
    "found invalid message: Signature was invalid"
  );
  t.end();
});

test("validation of first message (`seq` == 1) without `previous`", (t) => {
  db.onReady(() => {
    query(
      fromDB(db),
      toCallback((err, msgs) => {
        if (err) t.fail(err);
        // attempt validation of single message (assume `previous` is null)
        t.equal(validate.validateSingle(msgs[0]), null, "success");
        t.pass(`validated ${MESSAGES} messages`);
        t.end();
      })
    );
  });
});

test("validation of a single message with `previous`", (t) => {
  db.onReady(() => {
    query(
      fromDB(db),
      toCallback((err, msgs) => {
        if (err) t.fail(err);
        // attempt validation of single message (include previous message)
        t.equal(validate.validateSingle(msgs[1], msgs[0]), null, "success");
        t.pass(`validated ${MESSAGES} messages`);
        t.end();
      })
    );
  });
});

test("validation of a single message (`seq` > 1) without `previous`", (t) => {
  db.onReady(() => {
    query(
      fromDB(db),
      toCallback((err, msgs) => {
        if (err) t.fail(err);
        // attempt validation of a single message without `previous`
        t.match(
          validate.validateSingle(msgs[3]),
          /The first message of a feed must have seq of 1/,
          "found invalid message: The first message of a feed must have seq of 1"
        );
        t.end();
      })
    );
  });
});

test("batch validation of full feed", (t) => {
  db.onReady(() => {
    query(
      fromDB(db),
      toCallback((err, msgs) => {
        if (err) t.fail(err);
        // attempt validation of all messages (assume `previous` is null)
        t.equal(validate.validateBatch(msgs), null, "success");
        t.pass(`validated ${MESSAGES} messages`);
        t.end();
      })
    );
  });
});

test("batch validation of partial feed (previous seq == 1)", (t) => {
  db.onReady(() => {
    query(
      fromDB(db),
      toCallback((err, msgs) => {
        if (err) t.fail(err);
        // shift first msg into `previous`
        previous = msgs.shift();
        // attempt validation of all messages
        t.equal(validate.validateBatch(msgs, previous), null, "success");
        t.pass(`validated ${MESSAGES} messages`);
        t.end();
      })
    );
  });
});

test("batch validation of partial feed (previous seq > 1)", (t) => {
  db.onReady(() => {
    query(
      fromDB(db),
      toCallback((err, msgs) => {
        if (err) t.fail(err);
        // skip first msg in the array
        first = msgs.shift();
        // shift second msg into `previous`
        previous = msgs.shift();
        // attempt validation of all messages
        t.equal(validate.validateBatch(msgs, previous), null, "success");
        t.pass(`validated ${MESSAGES} messages`);
        t.end();
      })
    );
  });
});

test("batch validation of partial feed without `previous`", (t) => {
  db.onReady(() => {
    query(
      fromDB(db),
      toCallback((err, msgs) => {
        if (err) t.fail(err);
        // shift first msg into `previous`
        previous = msgs.shift();
        // attempt validation of all messages without `previous`
        t.match(
          validate.validateBatch(msgs),
          /The first message of a feed must have seq of 1/,
          "found invalid message: The first message of a feed must have seq of 1"
        );
        t.end();
      })
    );
  });
});

test("batch validation of out-of-order messages", (t) => {
  db.onReady(() => {
    query(
      fromDB(db),
      toCallback((err, msgs) => {
        if (err) t.fail(err);
        // shuffle the messages (generate out-of-order state)
        msgs.sort(() => Math.random() - 0.5);
        // attempt validation of all messages
        t.equal(validate.validateOOOBatch(msgs), null, "success");
        t.pass(`validated ${MESSAGES} messages`);
        t.end();
      })
    );
  });
});
