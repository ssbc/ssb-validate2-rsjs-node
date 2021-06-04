#!/bin/bash

# On iOS nodejs-mobile we need index.node to be a folder that will be converted
# to a .framework
if [ "$npm_config_platform" == "ios" ]; then
  mv dist/index.node dist/index
  mkdir dist/index.node
  mv dist/index dist/index.node/index
fi
