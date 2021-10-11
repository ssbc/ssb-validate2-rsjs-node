// SPDX-FileCopyrightText: 2021 Andre 'Staltz' Medeiros
//
// SPDX-License-Identifier: LGPL-3.0-only

const fs = require('fs');
const path = require('path');
const child_process = require('child_process');
const loader = require('node-bindgen-loader');
const pkg = require('./package.json');

async function copy(orig, dest) {
  const st = await fs.promises.stat(orig);
  const buf = await fs.promises.readFile(orig);
  await fs.promises.writeFile(dest, buf);
  await fs.promises.chmod(dest, st.mode);
}

function mkdirp(folder) {
  if (fs.existsSync(folder)) return;
  try {
    fs.mkdirSync(folder);
  } catch (err) {}
}

function spawn(cmd) {
  const [head, ...rest] = cmd.split(' ')
  return new Promise((resolve, reject) => {
    const proc = child_process.spawn(head, rest)
    proc.stdout.on('data', (data) => {
      process.stdout.write(data)
    })
    proc.stderr.on('data', (data) => {
      process.stderr.write(data)
    })
    proc.on('close', (code) => {
      resolve(code)
    })
    proc.on('error', (err) => {
      reject(err)
    })
  })
}

function isGitRepo() {
  return fs.existsSync(path.join(__dirname, '.git'));
}

function prebuildExists() {
  try {
    const result = loader({dir: __dirname});
    return !!result
  } catch (err) {
    return false
  }
}

const ext = {
  android: 'so',
  ios: 'dylib',
};

(async function main() {
  // `npm_config_platform` is set when nodejs-mobile is controlling npm install
  // in order to build native modules, so we build our module here and move it
  // correctly
  const platform = process.env['npm_config_platform'];

  if (platform === 'android' || platform === 'ios') {
    mkdirp(path.join(__dirname, 'dist'));
    await spawn('cargo build --release')
    const TARGET = process.env['CARGO_BUILD_TARGET'];
    const LIBNAME = 'lib' + pkg.name.replace(/-/g, '_') + '.' + ext[platform];
    copy(
      path.join(__dirname, 'target', TARGET, 'release', LIBNAME),
      path.join(__dirname, 'dist', 'index.node'),
    );
  } else if (!isGitRepo() && !prebuildExists()) {
    await spawn('nj-cli build --release')
  }
})();
