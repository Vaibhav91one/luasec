'use strict';
// End-to-end check of the npm launcher against a tarball built from this
// checkout, the way the release job builds it: tracked files plus vendor/.
const { execFileSync, spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const assert = require('assert');

const repo = path.resolve(__dirname, '..');
const pkg = require('./package.json');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'luasec-npm-'));
const name = `luasec-${pkg.version}`;
const tarball = path.join(tmp, `${name}.tar.gz`);
const stage = path.join(tmp, 'stage', name);

fs.mkdirSync(stage, { recursive: true });
const tracked = execFileSync('git', ['ls-files'], { cwd: repo, encoding: 'utf8' }).split('\n').filter(Boolean);
for (const file of tracked.concat(execFileSync('find', ['vendor/luacheck', '-type', 'f'], { cwd: repo, encoding: 'utf8' }).split('\n').filter(Boolean))) {
  fs.mkdirSync(path.join(stage, path.dirname(file)), { recursive: true });
  fs.copyFileSync(path.join(repo, file), path.join(stage, file));
}
fs.chmodSync(path.join(stage, 'bin', 'luasec'), 0o755);
execFileSync('tar', ['czf', tarball, '-C', path.join(tmp, 'stage'), name]);

const env = Object.assign({}, process.env, { LUASEC_TARBALL: tarball, LUASEC_CACHE: path.join(tmp, 'cache') });
const launcher = path.join(__dirname, 'bin', 'luasec.js');
const run = (args) => spawnSync(process.execPath, [launcher].concat(args), { env, encoding: 'utf8' });

const version = run(['--version']);
assert.strictEqual(version.status, 0, version.stderr);
assert.match(version.stdout, new RegExp(`^luasec ${pkg.version.replace(/\./g, '\\.')} `));

const finding = run([path.join(repo, 'test/fixtures/tainted_exec/handler.lua')]);
assert.strictEqual(finding.status, 1, finding.stderr);
assert.match(finding.stdout, /\[709\] critical/);

const again = run(['--score', path.join(repo, 'test/fixtures/clean/report.lua')]);
assert.strictEqual(again.status, 0, again.stderr);
assert.strictEqual(again.stdout.trim(), '100');

fs.rmSync(tmp, { recursive: true, force: true });
console.log('npm launcher: ok');
