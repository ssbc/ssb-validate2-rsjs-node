// SPDX-FileCopyrightText: 2021 Andrew 'glyph' Reid
//
// SPDX-License-Identifier: Unlicense

const validate = require("../");
const legacyValidate = require("ssb-validate");
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
const dir = "/tmp/validate-benchmark";
const oldLogPath = path.join(dir, "flume", "log.offset");
const newLogPath = path.join(dir, "flume", "log.bipf");
const indexesDir = path.join(dir, "indexes");

// generate fixture
rimraf.sync(dir, { maxBusyTries: 3 });
mkdirp.sync(dir);

const SEED = "sloop";
const MESSAGES = 100;
const AUTHORS = 1;
// run each test x times
const ITERATIONS = 10;

const hmacKey = null;

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
  const start = Date.now();
  raf = Log(newLogPath, { blockSize: 64 * 1024 });
  rimraf.sync(indexesDir);
  db = JITDB(raf, indexesDir);
  db.onReady(() => {
    const duration = Date.now() - start;
    t.pass(`duration: ${duration}ms`);
    t.end();
  });
});

// batch verification of signatures for an array of messages
test("verifySignatures", (t) => {
  t.plan(ITERATIONS);
  db.onReady(() => {
    query(
      fromDB(db),
      toCallback((err, kvtMsgs) => {
        if (err) t.fail(err);
        // map msgs to msg.value for each
        const msgs = kvtMsgs.map(msg => msg.value);
        var i;
        var totalDuration = 0;
        for (i = 0; i < ITERATIONS; i++) {
          const start = Date.now();
          validate.verifySignatures(hmacKey, msgs, () => {
            const duration = Date.now() - start;
            totalDuration += duration;
            t.pass(`verified ${MESSAGES} message signatures in ${duration} ms`);
          });
        }
        avgDuration = totalDuration / ITERATIONS;
        console.log(`average duration: ${avgDuration} ms`);
        t.end();
      })
    );
  });
});

// verification and validation for a single message
test("validateSingle", (t) => {
  t.plan(ITERATIONS);
  db.onReady(() => {
    query(
      fromDB(db),
      toCallback((err, kvtMsgs) => {
        if (err) t.fail(err);
        var i;
        var totalDuration = 0;
        for (i = 0; i < ITERATIONS; i++) {
          // validate a single message (`seq` == 1)
          const start = Date.now();
          validate.validateSingle(hmacKey, kvtMsgs[0].value, null, () => {
            const duration = Date.now() - start;
            totalDuration += duration;
            t.pass(`validated 1 message in ${duration} ms`);
          });
        }
        avgDuration = totalDuration / ITERATIONS;
        console.log(`average duration: ${avgDuration} ms`);
        t.end();
      })
    );
  });
});

// batch verification and validation for an array of messages
test("validateBatch", (t) => {
  t.plan(ITERATIONS);
  db.onReady(() => {
    query(
      fromDB(db),
      toCallback((err, kvtMsgs) => {
        if (err) t.fail(err);
        // map msgs to msg.value for each
        const msgs = kvtMsgs.map(msg => msg.value);
        var i;
        var totalDuration = 0;
        for (i = 0; i < ITERATIONS; i++) {
          // validate array of successive messages from a feed
          const start = Date.now();
          validate.validateBatch(hmacKey, msgs, null, () => {
            const duration = Date.now() - start;
            totalDuration += duration;
            t.pass(`validated ${MESSAGES} messages in ${duration} ms`);
          });
        }
        avgDuration = totalDuration / ITERATIONS;
        console.log(`average duration: ${avgDuration} ms`);
        t.end();
      })
    );
  });
});

// batch verification and validation for an array of out-of-order messages
test("validateOOOBatch", (t) => {
  t.plan(ITERATIONS);
  db.onReady(() => {
    query(
      fromDB(db),
      toCallback((err, kvtMsgs) => {
        if (err) t.fail(err);
        // map msgs to msg.value for each
        const msgs = kvtMsgs.map(msg => msg.value);
        var i;
        var totalDuration = 0;
        for (i = 0; i < ITERATIONS; i++) {
          const start = Date.now();
          // shuffle array of msgs to generate out-of-order state
          msgs.sort(() => Math.random() - 0.5);
          validate.validateOOOBatch(hmacKey, msgs, () => {
            const duration = Date.now() - start;
            totalDuration += duration;
            t.pass(`validated ${MESSAGES} messages in ${duration} ms`);
          });
        }
        avgDuration = totalDuration / ITERATIONS;
        console.log(`average duration: ${avgDuration} ms`);
        t.end();
      })
    );
  });
});

test("append (legacy validation)", (t) => {
  db.onReady(() => {
    query(
      fromDB(db),
      toCallback((err, kvtMsgs) => {
        if (err) t.fail(err);
        // map msgs to msg.value for each
        const msgs = kvtMsgs.map(msg => msg.value);
        var i;
        var totalDuration = 0;
        for (i = 0; i < ITERATIONS; i++) {
          var state = legacyValidate.initial();
          const start = Date.now();
          msgs.forEach(function (msg) {
            try {
              state = legacyValidate.append(state, hmacKey, msg);
            } catch (err) {
              console.log(err);
            }
          });
          const duration = Date.now() - start;
          totalDuration += duration;
          t.pass(`validated ${MESSAGES} messages in ${duration} ms`);
        }
        avgDuration = totalDuration / ITERATIONS;
        console.log(`average duration: ${avgDuration} ms`);
        t.end();
      })
    );
  });
});
