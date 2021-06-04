#!/bin/bash

# `npm_config_platform` is set when nodejs-mobile is controlling npm install
# in order to build native modules, so we build our module here and move it
# correctly
if [ "$npm_config_platform" == "android" ]; then
  cd native
  mkdir -p dist
  cargo build --release
  cd ..
  cp ./target/$CARGO_BUILD_TARGET/release/libssb_validate2_rsjs.so ./native/dist/index.node
elif [ "$npm_config_platform" == "ios" ]; then
  cd native
  mkdir -p dist
  cargo build --release
  cd ..
  cp ./target/$CARGO_BUILD_TARGET/release/libssb_validate2_rsjs.dylib ./native/dist/index.node
fi
