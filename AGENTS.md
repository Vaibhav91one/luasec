# luasec - agent conventions

Read before touching anything. Single source of truth for how work is done here.
Do not deviate without updating this file in the same PR.

## What this tool is

`luasec` is a static RCE / security analyzer for Lua source found in embedded firmware.
It reuses `luacheck` (vendored, MIT) as a library: its lexer/parser give a real
Lua 5.1-5.4 + LuaJIT AST, and its `linearize` + `resolve_locals` stages give a
linearized CFG plus flow-sensitive reaching-definitions. We add what luacheck has no
concept of: taint, sinks, sources, severity, CWE mapping, SARIF.

We never modify `vendor/`. It is pinned (see `vendor/PINNED`) and checked by
`make vendor-verify`.

## TDD discipline (non-negotiable)

1. One behavior -> one failing test -> minimal code -> pass. Repeat.
2. NEVER write a batch of tests then a batch of implementation. That yields tests
   written against imagined behavior.
3. Refactor only while GREEN.
4. If a test breaks because you renamed a private function, the test was wrong.
5. Every new warning code needs: registry entry (CWE + severity), a doc row, one
   firing fixture and one silent fixture.

### Public seams - the only things tests may use

| Seam | Interface |
| --- | --- |
| library | `require("luasec.api")` -> `check_source(src, opts)`, `analyze(paths, opts)`, `format(report, name)`, `rules.load(path)`, `validate_payload(src, opts)` |
| CLI | `bin/luasec <args>` as a subprocess (flags, exit codes, stdout contracts) |
| allowed extra | `luasec.util.util` (string/entropy helpers), `luasec.util.const_eval` (constant folding), `luasec.bytecode.detect`, `luasec.bytecode.header`, `luasec.bytecode.protos` - public modules in their own right, each with a narrow interface |

Forbidden in tests: `require("luacheck.*")`, the `stages.warnings` table shape,
anything under `luasec.engine.*`, `luasec.report.*` internals, private functions,
mocks of internal collaborators, and verifying through a side channel (e.g. reading
a cache file to prove a write happened).

A test that asserts on a spec fixture in `test/selfcheck/` is only ever run by
`make runner-selftest`; `make test` must stay green.

Test names describe behavior, not mechanism:
`"tainted HTTP parameter reaching os.execute is reported as 709 critical"` = good.
`"taint.lua calls check_sink"` = bad.

## Layout

    src/luasec/
      api.lua          public entry points
      main.lua         CLI entry
      cli/             args, config, walk, baseline
      engine/          pipeline, taint, callgraph, const_eval, sanitizers, directives
      rules/           code registry + rule modules
      registry/        platform API registry + firmware std data
      bytecode/        magic sniff, header, prototypes
      validate/        payload validator sandbox
      report/          json, sarif, plain, html
      util/            small shared helpers
    test/
      run.lua          zero-dep runner: `make test`
      spec/            behavior specs, one file per area
      fixtures/        inputs referenced by specs
      adversarial/     written by the verifier, kept as regressions

## Commands

    make            # build lua + vendor + test
    make test       # run all specs
    make ci-verify  # full gate: vendor-verify, upstream luacheck specs, our specs, adversarial
    make tdd-proof BASE HEAD   # reverse-apply src/ only, run new tests, expect failure
    make ci         # what GitHub Actions runs

A spec file that must fail is named `test/spec/zz_failing_spec.lua` and is excluded
from `make test`; `make runner-selftest` runs it and asserts a non-zero exit.

## Measuring memory - read this before quoting any RSS number

`/usr/bin/time -l` **misreports the unit of its `maximum resident set size` field
on macOS.** On this build it prints **bytes**, not the kilobytes macOS documents
for it. The trap is the obvious one: read the field as kilobytes and every number
is inflated by 1024x. `/usr/bin/time -l build/lua-5.4.9/src/lua -e 'print("hi")'`
prints `1687552`, which looks like 1.6GB and is actually 1.6MB - the real value.
It is not an offset and it is not a broken tool; it is a different unit than the
one its own documentation implies. Read the raw field as **bytes**.

Do not trust the byte reading on the strength of that argument alone, because
`time` is a single source. Measure with `getrusage` and check that it agrees:

    cat > /tmp/peak.py <<'PY'
    import resource, subprocess, sys, time
    cmd = sys.argv[1:]
    t0 = time.time()
    p = subprocess.run(cmd, capture_output=True, text=True)
    el = time.time() - t0
    ru = resource.getrusage(resource.RUSAGE_CHILDREN)
    print("exit=%d  elapsed=%.2fs  peak_child_rss=%.1f MB" % (p.returncode, el, ru.ru_maxrss/1048576.0))
    for line in (p.stdout + p.stderr).strip().splitlines()[:8]: print("   ", line)
    PY

    python3 /tmp/peak.py ./bin/luasec --validate <payload>

Calibrate any new harness on something with a known footprint before trusting it
- a payload whose size you chose yourself is the only honest control.

Two traps in `getrusage` itself, both of which have bitten this repo:

- `RUSAGE_CHILDREN` is a **cumulative high-water mark across every child the
  process has ever reaped**, and it never resets. Sweep several payloads inside
  one Python process and the first large one poisons every row after it. Sample in
  a fresh process per measurement, as `peak.py` above does.
- On Linux `ru_maxrss` is in kilobytes; on macOS it is in bytes. The same script
  is off by 1024x across platforms.

Report the **worst of at least 3 runs**, never a single sample. The resident set
of the validator's doubling payload on this machine ranged 103.0MB to 178.69MB
over batches of 10 - a 1.7x spread inside one configuration. A single run is not
a measurement of a distribution this wide, and a number quoted from one is not
reproducible.

## Warning codes

| Range | Meaning |
| --- | --- |
| 701-712 | command execution / dynamic code sinks |
| 721-728 | firmware-specific (flash, uci chain, sandbox escape, DoS) |
| 741-750 | payload / backdoor patterns |
| 801-805 | artifact / bytecode |
| 901-903 | meta (parse failed, unsupported dialect, dialect mismatch) |

The 0xx-6xx range is luacheck's vocabulary and a luasec code must not collide with
one it uses. The reserved set is enumerated in
`test/spec/rules_catalogue_spec.lua` and a spec fails the build on a collision.
`012` is the one luasec code in that range: luasec sat on 021, which is
luacheck's, so a finding meant one thing in this tool's output and another in
luacheck's.

Every code carries `severity` (critical/high/medium/low), `confidence`
(certain/high/medium/low), and `cwe` where a CWE applies. Codes are registered in
`src/luasec/rules/codes.lua` and documented in `docs/rules.md`; a spec asserts every
registered code has a doc row.

## Commit / PR conventions

- One issue = one branch `issue/<n>-<slug>` = one PR. Body starts with `Closes #<n>`.
- Squash merge. Do not merge your own PR; the orchestrator merges after verification.
- Do not touch files outside your issue's declared owned paths.
- Never push to `main`, never create merge commits, never run `gh pr merge`.

## Verifier subagent

An independent agent reviews every PR: spec compliance first, then code quality, then
`make tdd-proof`, metamorphic invariants, corpus oracle, precision budget, and a
security review of luasec itself. Its verdict blocks merge. Fix what it legitimately
raises; argue in the PR when it is wrong.
