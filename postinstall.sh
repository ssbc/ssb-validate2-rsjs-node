#!/bin/bash

# On iOS nodejs-mobile we need index.node to be a folder that will be converted
# to a .framework
if [ "$npm_config_platform" == "ios" ]; then
  mv native/dist/index.node native/dist/index
  mkdir native/dist/index.node
  mv native/dist/index native/dist/index.node/index
fi
