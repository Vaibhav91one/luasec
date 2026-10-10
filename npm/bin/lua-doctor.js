#!/usr/bin/env node
'use strict';
// npx @doctor-labs/lua-doctor: fetch the lua-doctor release that matches this package's version into
// a cache directory once, then run it. Nothing but Node built-ins, the system
// tar, and (only when no Lua 5.3+ is on PATH) make and a C compiler.
const { spawnSync } = require('child_process');
const fs = require('fs');
const https = require('https');
const os = require('os');
const path = require('path');

const { version } = require('../package.json');
const name = `lua-doctor-${version}`;
const url = `https://github.com/doctor-labs/lua-doctor/releases/download/v${version}/${name}.tar.gz`;
const cache = process.env.LUA_DOCTOR_CACHE
  || path.join(process.env.XDG_CACHE_HOME || path.join(os.homedir(), '.cache'), 'lua-doctor');
const root = path.join(cache, name);
const entry = path.join(root, 'bin', 'lua-doctor');

function fail(message) {
  process.stderr.write(`lua-doctor (npm): ${message}\n`);
  process.exit(2);
}

function download(from, to, redirects = 5) {
  return new Promise((resolve, reject) => {
    https.get(from, (res) => {
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location && redirects > 0) {
        res.resume();
        resolve(download(res.headers.location, to, redirects - 1));
        return;
      }
      if (res.statusCode !== 200) {
        res.resume();
        reject(new Error(`GET ${from}: HTTP ${res.statusCode}`));
        return;
      }
      const out = fs.createWriteStream(to);
      res.pipe(out);
      out.on('finish', () => out.close(resolve));
      out.on('error', reject);
    }).on('error', reject);
  });
}

function hasLua() {
  const probe = spawnSync('lua', ['-e', 'os.exit(tonumber(_VERSION:match("%d+%.%d+")) >= 5.3 and 0 or 1)']);
  return probe.status === 0;
}

async function install() {
  fs.mkdirSync(cache, { recursive: true });
  const staging = fs.mkdtempSync(path.join(cache, '.staging-'));
  const tarball = process.env.LUA_DOCTOR_TARBALL || path.join(staging, `${name}.tar.gz`);
  if (!process.env.LUA_DOCTOR_TARBALL) {
    process.stderr.write(`lua-doctor (npm): downloading ${url}\n`);
    await download(url, tarball);
  }
  const untar = spawnSync('tar', ['xzf', tarball, '-C', staging], { stdio: 'inherit' });
  if (untar.status !== 0) fail(`cannot extract ${tarball}`);
  if (!fs.existsSync(path.join(staging, name, 'bin', 'lua-doctor'))) fail(`${tarball} has no ${name}/bin/lua-doctor`);
  if (!hasLua()) {
    process.stderr.write('lua-doctor (npm): no Lua 5.3+ on PATH; building Lua once with make (needs a C compiler)\n');
    const built = spawnSync('make', ['lua'], { cwd: path.join(staging, name), stdio: ['ignore', 2, 2] });
    if (built.status !== 0) fail('building Lua failed; install Lua 5.3+ or a C compiler and try again');
  }
  try {
    fs.renameSync(path.join(staging, name), root);
  } catch (error) {
    // Another first run finished installing the same version while this one
    // was extracting: use its copy.
    if (!fs.existsSync(entry)) throw error;
  }
  fs.rmSync(staging, { recursive: true, force: true });
}

(async () => {
  if (!fs.existsSync(entry)) {
    try {
      await install();
    } catch (error) {
      fail(error.message);
    }
  }
  const result = spawnSync(entry, process.argv.slice(2), { stdio: 'inherit' });
  if (result.error) fail(result.error.message);
  process.exit(result.status === null ? 2 : result.status);
})();
