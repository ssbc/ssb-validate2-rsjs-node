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
const dir = "/tmp/validate-multi-benchmark";
const oldLogPath = path.join(dir, "flume", "log.offset");
const newLogPath = path.join(dir, "flume", "log.bipf");
const indexesDir = path.join(dir, "indexes");

// generate fixture
rimraf.sync(dir, { maxBusyTries: 3 });
mkdirp.sync(dir);

const SEED = "sloop";
const MESSAGES = 100;
const AUTHORS = 5;
// run each test x times
const ITERATIONS = 10;

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

// batch verification and validation for an array of multi-author out-of-order messages
test("validateMultiAuthorBatch", (t) => {
  t.plan(ITERATIONS);
  db.onReady(() => {
    query(
      fromDB(db),
      toCallback((err, msgs) => {
        if (err) t.fail(err);
        var i;
        var totalDuration = 0;
        for (i = 0; i < ITERATIONS; i++) {
          // shuffle array of msgs to generate out-of-order state
          msgs.sort(() => Math.random() - 0.5);
          const start = Date.now();
          validate.validateMultiAuthorBatch(msgs, () => {
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

test("appendKVT (legacy validation)", (t) => {
  db.onReady(() => {
    query(
      fromDB(db),
      toCallback((err, msgs) => {
        if (err) t.fail(err);
        var i;
        var totalDuration = 0;
        for (i = 0; i < ITERATIONS; i++) {
          var hmac_key = null;
          var state = legacyValidate.initial();
          const start = Date.now();
          msgs.forEach(function (msg) {
            try {
              state = legacyValidate.appendKVT(state, hmac_key, msg);
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
