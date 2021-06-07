const fs = require('fs');
const util = require('util');
const child_process = require('child_process');
const exec = util.promisify(child_process.exec);

async function copy(orig, dest) {
  const st = await fs.promises.stat(orig);
  const buf = await fs.promises.readFile(orig);
  await fs.promises.writeFile(dest, buf);
  await fs.promises.chmod(dest, st.mode);
}

async function mkdirp(folder) {
  if (fs.existsSync(folder)) return;
  try {
    fs.mkdirSync(folder);
  } catch (err) {}
}

const extensions = {
  android: 'so',
  ios: 'dylib',
};

(async function main() {
  // `npm_config_platform` is set when nodejs-mobile is controlling npm install
  // in order to build native modules, so we build our module here and move it
  // correctly
  const platform = process.env['npm_config_platform']

  if (platform === 'android' || platform === 'ios') {
    mkdirp('dist');
    const {stdout, stderr} = await exec('cargo build --release');
    console.log(stdout);
    console.error(stderr);
    const TARGET = process.env['CARGO_BUILD_TARGET'];
    const EXT = extensions[platform]
    copy(
      `target/${TARGET}/release/libssb_validate2_rsjs_node.${EXT}`,
      'dist/index.node',
    );
  }
})();
