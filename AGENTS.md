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
| allowed extra | `luasec.util.const_eval`, `luasec.bytecode.header` - public modules in their own right |

Forbidden in tests: `require("luacheck.*")`, the `stages.warnings` table shape,
anything under `luasec.engine.*`, private functions, mocks of internal collaborators,
and verifying through a side channel (e.g. reading a cache file to prove a write).

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

## Warning codes

| Range | Meaning |
| --- | --- |
| 701-712 | command execution / dynamic code sinks |
| 721-728 | firmware-specific (flash, uci chain, sandbox escape, DoS) |
| 741-750 | payload / backdoor patterns |
| 801-805 | artifact / bytecode |
| 901-903 | meta (parse failed, unsupported dialect, dialect mismatch) |

Codes 0xx-6xx belong to luacheck. Do not use them.

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
