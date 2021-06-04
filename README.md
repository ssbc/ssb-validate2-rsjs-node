# ssb-validate2-rsjs-node

Cryptographic validation of Scuttlebutt messages in the form of Rust bindings for Node.js.

Perform batch verification and validation of SSB messages using [ssb-verify-signatures](https://crates.io/crates/ssb-verify-signatures) and [ssb-validate](https://github.com/mycognosist/ssb-validate) from the [Sunrise Choir](https://github.com/sunrise-choir).

The [node-bindgen](https://github.com/infinyon/node-bindgen) crate is currently used to generate the bindings from Rust code.

## Build

Rust first needs to be installed in order to build the bindings ([installation instructions](https://rustup.rs/)).

```bash
git clone git@github.com:ssb-ngi-pointer/ssb-validate2-rsjs-node.git
cd ssb-validate2-rsjs-node
cargo install nj-cli
# generate release build of ssb-validate2-rsjs-node
npm run build
# run the tests
npm run test
```

The build process creates bindings in `./dist/index.node`.

If you wish to rebuild the bindings after making changes to the code, use the `nj-cli` tool:

`nj-cli build --release`

## Tests

Tests for single-author and multi-author messages are included. These tests are defined and executed using [tape](https://www.npmjs.com/package/tape). Test data (SSB messages) are dynamically-generated using [ssb-fixtures](https://github.com/ssb-ngi-pointer/ssb-fixtures). The tests can be found in the `native/test` directory.

## Performance Benchmarks

After performing build instructions (see above):

```bash
cd ssb-validate2-rsjs-node
# Run benchmarks
npm run perf
```

The default values for the performance benchmarks (`test/perf.js`) are 100 messages from 1 author, for a total of 10 iterations. These value constants can be changed in `test/perf.js`. Performance benchmarks for the multi-author method default to 100 messages from 5 authors, for a total of 10 iterations (`test/multiAuthorPerf.js`).

## License

AGPL 3.0.
