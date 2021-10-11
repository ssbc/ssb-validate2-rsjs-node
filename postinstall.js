// SPDX-FileCopyrightText: 2021 Andre 'Staltz' Medeiros
//
// SPDX-License-Identifier: LGPL-3.0-only

const fs = require('fs');
const path = require('path');

async function move(orig, dest) {
  await fs.promises.rename(orig, dest);
}

async function mkdirp(folder) {
  if (fs.existsSync(folder)) return;
  try {
    fs.mkdirSync(folder);
  } catch (err) {}
}

(async function main() {
  // npm_config_platform exists only when nodejs-mobile is building our module
  const platform = process.env['npm_config_platform'];

  // On iOS nodejs-mobile we need index.node to be a folder that
  // will be converted to a .framework
  if (platform === 'ios') {
    move(
      path.join(__dirname, 'dist', 'index.node'),
      path.join(__dirname, 'dist', 'index'),
    );
    mkdirp(path.join(__dirname, 'dist', 'index.node'));
    move(
      path.join(__dirname, 'dist', 'index'),
      path.join(__dirname, 'dist', 'index.node', 'index'),
    );
  }
})();
