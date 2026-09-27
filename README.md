# luasec

RCE checker and security analyzer for Lua found in embedded firmware.

`luasec` finds places where untrusted input reaches code or command execution in
Lua running on routers, cameras, inverters and other embedded devices, and it
hunts for malicious or backdoored Lua already present in a firmware image.

It reuses [luacheck](https://github.com/lunarmodules/luacheck) (MIT, vendored) as a
library: the lexer/parser handle Lua 5.1-5.4 and LuaJIT, and luacheck's `linearize`
and `resolve_locals` stages provide a control flow graph with flow-sensitive reaching
definitions. On top of that `luasec` adds taint tracking, sink and source rules,
severity, CWE mapping, firmware platform profiles, bytecode triage and SARIF output.

## Status

Early. See [docs/architecture.md](docs/architecture.md) for the design and
[docs/rules.md](docs/rules.md) for the rule catalogue.

## Build and test

```sh
make            # build Lua 5.4.9, fetch pinned luacheck, run the specs
make test       # specs only
make ci-verify  # the full gate
```

No luarocks and no C dependencies beyond a locally compiled Lua.

## Use

```sh
bin/luasec rootfs/usr/lib/lua/handler.lua
bin/luasec --format sarif --output findings.sarif rootfs/
bin/luasec --validate candidate-payload.lua
```

Exit codes: `0` clean, `1` findings at or above the threshold, `2` error.

`--validate` is the dynamic half: it runs one snippet in a child process with
`os` and `io` replaced by recorders, and reports whether the snippet actually
reaches execution. It exits `0` for benign, `1` for rce, partial or timeout and
`2` when the payload or the sandbox itself failed. The verdict names the file and
the interpreter it came from, and any text the snippet itself produced - what it
printed, what it returned, the argument it passed to a sink, its own error
message - is labelled as the snippet's rather than presented as a finding. See
[docs/architecture.md](docs/architecture.md#the-payload-validator).

## Why firmware

Embedded Lua is frequently the web layer of a device that runs as root: a LuCI
handler, an HTTP API, a CGI script, a config generator. Attacker-controlled input
flowing into `os.execute` there is remote code execution as root on a device that
is rarely patched and often has no shell. `luasec` treats that flow as the primary
bug class and profiles the platforms where it happens (OpenWrt/LuCI, OpenResty,
LuaJIT, HiSilicon, ESP).

## License

MIT. Vendored luacheck is MIT, see `vendor/luacheck/LICENSE`.
