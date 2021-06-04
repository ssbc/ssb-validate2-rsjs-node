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
const dir = "/tmp/validate-multi-test";
const oldLogPath = path.join(dir, "flume", "log.offset");
const newLogPath = path.join(dir, "flume", "log.bipf");
const indexesDir = path.join(dir, "indexes");

// generate fixture
rimraf.sync(dir, { maxBusyTries: 3 });
mkdirp.sync(dir);

const SEED = "sloop";
const MESSAGES = 10;
const AUTHORS = 2;

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

test("batch validation of out-of-order multi-author messages", (t) => {
  db.onReady(() => {
    query(
      fromDB(db),
      toCallback((err, msgs) => {
        if (err) t.fail(err);
        // shuffle the messages (generate out-of-order state)
        msgs.sort(() => Math.random() - 0.5);
        // attempt validation of all messages
        t.equal(validate.validateMultiAuthorBatch(msgs), null, "success");
        t.pass(`validated ${MESSAGES} messages`);
        t.end();
      })
    );
  });
});
