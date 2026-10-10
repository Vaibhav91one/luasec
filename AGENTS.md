# lua-doctor - agent conventions

Read before touching anything. Single source of truth for how work is done here.
Do not deviate without updating this file in the same PR.

## What this tool is

`lua-doctor` is a static RCE / security analyzer for Lua source found in embedded firmware.
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
   firing fixture and one silent fixture, a docs/rules/<code>.md page (checked by test/spec/rule_docs_spec.lua).

### Public seams - the only things tests may use

| Seam | Interface |
| --- | --- |
| library | `require("luadoctor.api")` -> `check_source(src, opts)`, `analyze(paths, opts)`, `format(report, name, opts)`, `score(report)`, `rules_load(paths)`, `validate_payload(src, opts)` |
| CLI | `bin/lua-doctor <args>` as a subprocess (flags, exit codes, stdout contracts) |
| allowed extra | `luadoctor.util.util` (string/entropy helpers), `luadoctor.util.const_eval` (constant folding), `luadoctor.bytecode.detect`, `luadoctor.bytecode.header`, `luadoctor.bytecode.protos` - public modules in their own right, each with a narrow interface |

Forbidden in tests: `require("luacheck.*")`, the `stages.warnings` table shape,
anything under `luadoctor.engine.*`, `luadoctor.report.*` internals, private functions,
mocks of internal collaborators, and verifying through a side channel (e.g. reading
a cache file to prove a write happened).

A test that asserts on a spec fixture in `test/selfcheck/` is only ever run by
`make runner-selftest`; `make test` must stay green.

Test names describe behavior, not mechanism:
`"tainted HTTP parameter reaching os.execute is reported as 709 critical"` = good.
`"taint.lua calls check_sink"` = bad.

## Layout

    src/luadoctor/
      api.lua          public entry points
      main.lua         CLI entry
      cli/             args, baseline, walk
      engine/          pipeline, parse_context, taint, callgraph, interprocedural, whole_program, inline_directives
      rules/           code registry + rule modules
      registry/        platform API registry + firmware std data
      bytecode/        magic sniff, header, prototypes
      validate/        payload validator sandbox
      report/          findings, render, json, sarif, plain, html
      util/            util, const_eval
    test/
      run.lua          zero-dep runner: `make test`
      spec/            behavior specs, one file per area
      fixtures/        inputs referenced by specs
      adversarial/     written by the verifier, kept as regressions

## Commands

    make            # build lua + vendor + test
    make test       # run all specs
    make ci-verify  # full local suite, kept for release: not the per-PR merge gate
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

`collectgarbage("count")` **returns kilobytes, not bytes** - the `time -l` trap
above, in the opposite direction. `LUA_GCCOUNT` computes `gettotalbytes(g) >> 10`
internally, so `math.floor(count)` is a KiB figure, `count / 1024` is MiB, and a
reading used as bytes is wrong by 1024x. A million-entry table calibrates it:

    local t = {} for i = 1, 1e6 do t[i] = i end
    print(collectgarbage("count"))   --> 16406.24609375

That is the ~16MB the table really costs; read as bytes it would be 16KB for a
million slots, which is impossible. While fixing #251 an agent double-divided a
reading and got `0.1 kB per file`; the primary bound test passed vacuously and
only its regression guard caught it.

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

    python3 /tmp/peak.py ./bin/lua-doctor --validate <payload>

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
| 012 | unreadable `-- lua-doctor:` suppression directive |
| 701-712 | command execution / dynamic code sinks |
| 721-731 | firmware-specific (flash, uci chain, sandbox escape, DoS, store hop, HTTP header and subrequest writes) |
| 741-750 | payload / backdoor patterns |
| 801-805 | artifact / bytecode |
| 901-904 | meta (901-903 parse failed, unsupported dialect, dialect mismatch; 904 analysis degraded on a large file, results approximate, never threshold-filterable) |

Every registered code is in this table. The ranges contain gaps because not
every number in them is registered.

Codes that mean a file was **not fully analyzed** rather than clean are never
filtered out by `--severity-threshold` and always fail the run: `012`, `801`,
`803`, `805`, `901`, `902`, `904`. That is a set, not a property of one code -
`904` is only the newest member of it - and `src/luadoctor/rules/degraded.lua` is
the single list of them, read by the exit code, the threshold exemption and the
baseline. `903` is deliberately not in it: it reports an API the configured Lua
standard does not have, a statement about the profile rather than a gap in what
was read.

The 0xx-6xx range is luacheck's vocabulary and a lua-doctor code must not collide with
one it uses. The reserved set is enumerated in
`test/spec/rules_catalogue_spec.lua` and a spec fails the build on a collision.
`012` is the one lua-doctor code in that range: lua-doctor sat on 021, which is
luacheck's, so a finding meant one thing in this tool's output and another in
luacheck's.

Every code carries `severity` (critical/high/medium/low), `confidence`
(certain/high/medium/low), and `cwe` where a CWE applies. Codes are registered in
`src/luadoctor/rules/codes.lua` and documented in `docs/rules.md`; a spec asserts every
registered code has a doc row. That spec covers `docs/rules.md` only - it cannot
read the table above - so when you add a code, update this table in the same PR or
nothing will tell you it is stale.

## Commit / PR conventions

- One issue = one branch `issue/<n>-<slug>` = one PR. Body starts with `Closes #<n>`.
- Squash merge. An agent never merges its own PR.
- The orchestrator merges, and only once all four hold: the verifier's verdict on
  **that PR** is a pass, the specs that PR touches are green locally, Actions is
  green on the PR, and the PR touches only the paths its issue declares.
  The local leg is deliberately the **subset**, not `make ci-verify`: Actions'
  `gate` job runs every step `ci-verify` runs and adds `tdd-proof` and
  `selfscan`, so the full run is duplicated work costing roughly 45 minutes per PR
  against a targeted spec's ~18 seconds. `test/run.lua` takes spec files as well
  as directories, so run the touched specs directly. A subset cannot catch a spec
  the PR did not touch breaking, which is acceptable **because CI runs the whole
  suite anyway** - the local run is an optimisation and must never be the thing
  that decides. Keep `make ci-verify` for release, and any local `make precision`,
  that one included, is evidence only under **`PRECISION_REQUIRE_CORPUS=1`**:
  without it the target prints `PASS` while skipping the corpus measurement
  entirely, and a skipped measurement is not evidence (#233). CI avoids that trap
  by running `make corpus` first.
- The orchestrator merges one PR at a time, in issue order, with
  `gh pr merge --squash --delete-branch`. Never two against `main` at once, and never
  a merge commit: squash is what keeps one issue mapped to one commit, which is what
  `make tdd-proof` reads.
- A PR with no behavior change (dead code, documentation) is labelled `type:chore` or `type:docs`, which skips the TDD proof; the label is reviewed like code, and a PR that changes behavior never carries it.
- Do not touch files outside your issue's declared owned paths.
- `main` stays protected regardless: never push to `main`, never force-push, never
  rewrite published history, never close an issue nobody opened.
- If any of the four conditions fails, the orchestrator stops and reports. It never
  merges with `--admin`, never re-runs a gate hoping for a different answer, and never
  works around a refusal. A blocked merge is a result to report, not a problem to route
  around.

## Verifier subagent

An independent agent reviews every PR: spec compliance first, then code quality, then
`make tdd-proof`, metamorphic invariants, corpus oracle, precision budget, and a
security review of lua-doctor itself. Its verdict blocks merge. Fix what it legitimately
raises; argue in the PR when it is wrong.
