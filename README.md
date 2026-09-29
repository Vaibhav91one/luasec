# luasec

Finds remote code execution in Lua that ships inside embedded firmware.

`luasec` answers one question about a firmware image: **can attacker-controlled
input reach code or command execution?** Embedded Lua is frequently the web
layer of a device running as root — a LuCI handler, an HTTP API, a CGI script, a
config generator. Input flowing into `os.execute` there is RCE as root on a
device that is rarely patched and often has no shell.

It also hunts for malicious or backdoored Lua already sitting in the image:
obfuscated loaders, decoded payloads reaching a sink, default credentials,
anti-analysis tricks, and files that are not really the source they claim to be.

```sh
bin/luasec --std +openwrt+luci rootfs/            # scan a rootfs
bin/luasec --format sarif -o findings.sarif .    # for a code-scanning dashboard
bin/luasec --validate candidate-payload.lua       # run one snippet, sandboxed
```

---

## What it is

A static analyzer built on [luacheck](https://github.com/lunarmodules/luacheck)
(MIT, vendored) as a library. luacheck's lexer and parser give a real
Lua 5.1–5.4 and LuaJIT AST; its `linearize` and `resolve_locals` stages give a
control flow graph with flow-sensitive reaching definitions. On top of that
`luasec` adds what luacheck has no concept of:

| | |
| --- | --- |
| **Taint tracking** | flow-sensitive, across function boundaries, and across files with `--whole-program` |
| **Sources and sinks** | per platform, declared as data, extensible at runtime with `--rules` |
| **Firmware profiles** | OpenWrt/LuCI, OpenResty, LuaJIT, HiSilicon, ESP — each declaring its own std, sources and sinks |
| **Findings** | stable code, severity, confidence, CWE, and a source-to-sink trace |
| **Reports** | plain text, JSON, schema-validated SARIF 2.1.0, self-contained HTML |
| **Baseline** | report only what is new since a stored report |
| **Bytecode triage** | identify, parse the header, walk prototypes, and say clearly that it was not decompiled |
| **Payload validator** | run one snippet in a sandboxed child process and report whether it actually reaches execution |

37 registered rule codes. See [docs/rules.md](docs/rules.md).

## Measured behaviour

Not claims — a measurement, re-runnable, and checked in CI.

```sh
make corpus && make precision
```

Over **566 files** of real firmware Lua from upstream LuCI (current and the
`openwrt-18.06` branch, pinned to a commit), LuaJIT and the OpenWrt package
tree:

| | |
| --- | --- |
| Findings | **231** across 103 files (18%) |
| Severity | 11 critical, 174 high, 12 medium, 34 low |
| `709` untrusted data → execution | 5 |
| `724` execution sink exposed as an RPC handler | 27 |
| `708` exposed sink, input not visible in this file | 36 |
| Hardcoded credentials (`747`) | **0** — see below |

The per-code table is in [docs/precision.md](docs/precision.md). It has been
wrong three times, so it is now measured by `make precision` on every CI run and
the build fails if a single count moves.

**On `747` measuring zero:** that is not the rule being blind, it is this corpus
containing no hardcoded credential. A real firmware image does. The rule's
precision is measured by fixtures instead, and that is a real weakness of the
measurement — a rule can be completely broken for the shapes firmware uses and
this corpus will not notice, which has happened more than once.

## What it will not tell you

Stated plainly, because a security tool that overstates its coverage is worse
than one that does not have the feature.

- **Taint follows a function's return value, in one file and, with
  `--whole-program`, across files.** A local `id` or a module field `M.id` in the
  same file that hands its argument back is followed, so
  `os.execute(id(http.formvalue("h")))` is reported. With `--whole-program`, the
  return value of a function in a module bound with `local m = require "mod"`
  (e.g. `m.id(x)`) is followed too. A method call (`M:m`), a function passed as a
  value, and a `require(...)` called inline inside an expression are not: that
  flow is missed.
- **A call that returns a cursor is opaque to the credential rule.** A factory
  named `open_section()` that returns `uci.cursor()` is not recognised as a
  config handle, so a credential written through it is not reported.
- **Bytecode is triaged, never decompiled.** A `.luac` file is identified and
  its header and prototypes walked; its logic is not recovered.
- **One scan root is bounded.** A tree that resolves to more than 50,000 paths
  is reported as a coverage gap rather than walked forever. Raise it with
  `LUASEC_MAX_WALK_PATHS`. This exists because following a symlink to `/` turned
  a 4,000-file scan into a walk of the filesystem.
- **A file over the node budget (`--max-nodes`, default 20,000), or with
   functions nested more than 64 deep, is analysed approximately** and reported
   as `904`: flow-sensitive local resolution is skipped and results degrade to
   a single forward pass. This does not mean the file is clean.
- **Alias resolution is bounded at 4 definitions and 6 hops.** Past that the
  answer is "not a cursor", so a credential can be missed.
- **`--whole-program` is opt-in** and slower. It follows `require` edges and
  passes taint into a required module's parameters, and nothing else.
- **A symlink to a file outside the scanned tree is followed and read.** Point
  `luasec` at a tree you trust to be the tree you want read.

## Silence means it looked

A `luasec` run that reports nothing means every file it was pointed at was read
and nothing was found. Specifically:

- A file that could not be read, parsed, or only analyzed approximately is
  reported as `901`–`904`, and fails the run whatever `--fail-on` says.
- Those findings survive `--only` and `--severity-threshold`. They cannot be
  filtered into a green build.
- `--ignore 901` is the one way to remove them, and choosing it means accepting
  that the run covered less ground than it was asked to.
- A directory that cannot be read, and a symlink that does not resolve, are each
  reported as `901` against the path that could not be read, and the run fails.

This is enforced, not aspirational: one list of codes means "we did not read
this" ([`src/luasec/rules/degraded.lua`](src/luasec/rules/degraded.lua)) and the
exit code, the severity threshold and the baseline all read it.

## Suppressions

Findings are silenced with a comment in the source:

```lua
-- luasec: ignore 709          this one is genuinely false
-- luasec: ignore 74[0-9]      a class of codes
-- luasec: ignore 701:os.execute   one finding by name
-- luasec: push                open a region
-- luasec: ignore 701          scoped to the region
-- luasec: pop                 close it
```

A suppression written outside any region is file-wide. One written inside a
`push`/`pop` region lives and dies with it, which is the point of the pair.

A suppression `luasec` cannot read is reported as `012` and silences nothing. A
broken suppression never hides a finding — including a `only` directive whose
pattern is a typo, which selects nothing rather than everything. A pattern in a
file the tool did not write is a pattern nobody validated, and the guard around
it is `pcall`, not a trust decision.

## Exit codes

| | |
| --- | --- |
| `0` | clean |
| `1` | findings at or above the threshold, **or** ground not covered |
| `2` | error — bad flag, unreadable rules file, unreadable path |
| `3` | new findings since a `--baseline` |

`2` is deliberately distinct from `1`. A typo in a flag is a configuration
error and must not be reported to a CI as a security finding.

Under `--validate` a verification verdict maps to one of these three, with no
separate threshold or baseline:

| | |
| --- | --- |
| `0` | `benign` — the snippet ran and reached no sink |
| `1` | `rce`, `escape`, `partial`, or `timeout` — reached a sink or was stopped by a sandbox limit |
| `2` | `error` — the payload produced no usable verdict |

A verdict is an outcome, not a finding count: `1` means the snippet reached a
sink or the sandbox had to stop it, and `2` means no verdict could be produced.

## Build and test

```sh
make            # build Lua 5.4.9, fetch pinned luacheck, run the specs
make test       # 601 specs
make ci-verify  # the full gate, including the corpus measurement
make corpus     # clone the firmware corpora (network, gitignored)
```

No luarocks, no C dependencies beyond a locally compiled Lua. `vendor/luacheck`
is pinned by commit and `make vendor-verify` fails on any drift.

Runs on Linux and macOS. Not Windows: the walk in
[`src/luasec/cli/walk.lua`](src/luasec/cli/walk.lua) shells out to `find -H` and
`sh -c` through `io.popen`, and
[`src/luasec/validate/driver.lua`](src/luasec/validate/driver.lua) launches the
sandbox child with `io.popen` over `/bin/sh` plus `kill`, `ps` and `ulimit`.
Windows `io.popen` is `cmd.exe`, which has none of those tools, so neither the
directory walk nor the validator runs there.

CI runs the specs, an adversarial suite, a TDD proof on every pull request, the
`luasec` scan of itself, and `make precision` — which clones the corpora and
fails the build if a single finding count has moved. The last of those exists
because a rule regression once passed the entire gate: nothing in it had ever
executed the analyzer over the corpus.

## Documentation

| | |
| --- | --- |
| [docs/architecture.md](docs/architecture.md) | how the pipeline is layered and why |
| [docs/usage.md](docs/usage.md) | quick-start scan, --std profiles, output formats, CI, --validate |
| [docs/rules.md](docs/rules.md) | all 37 codes, severity, CWE |
| [docs/precision.md](docs/precision.md) | the measurement, and what it does not cover |
| [docs/firmware-stds.md](docs/firmware-stds.md) | what each platform profile declares |
| [docs/sarif.md](docs/sarif.md) | the report contract |
| [SECURITY.md](SECURITY.md) | threat model, and what the sandbox really bounds |
| [REVIEW.md](REVIEW.md) | how this was built and reviewed, and what is still open |

## Status

Beta. It finds real RCE in real firmware, its measurement is reproducible, and
its known limits are listed above rather than discovered by a user. It has had
adversarial review by independent AI agents, whose findings are fixed (see
REVIEW.md). It has not been reviewed by a human security researcher outside the
project.

## Why firmware

Because that is where this bug class is worth the effort. A web framework on a
laptop gets patched; a LuCI handler on a router that was manufactured in 2016
does not, and the device frequently has no shell to get a foothold on. The
profiles, the exit-code contract and the "silence means it looked" invariant are
all built around that one use.

## License

MIT. Vendored luacheck is MIT, see `vendor/luacheck/LICENSE`.
