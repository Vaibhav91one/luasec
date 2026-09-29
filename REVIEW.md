# REVIEW.md

How `luasec` was built, what the review process actually found, and what is still
open or uncertain. Written for someone deciding whether to trust it, and for
whoever picks it up next.

This is a different document from the [README](README.md). The README is the
tool. This is the account of the work, including the parts that are not
resolved.

---

## 1. What was built

A static RCE and security analyzer for Lua in embedded firmware: 40 rule codes,
taint analysis with flow-sensitive reaching definitions and cross-function
propagation, five firmware platform profiles, whole-program analysis across
`require` edges, bytecode triage, a sandboxed payload validator, and four
output formats.

- ~14,700 lines of implementation under `src/luasec/`
- 576 specs plus an 8-case adversarial suite
- 52 commits on `main`
- Built on luacheck as a library, vendored and pinned by commit

The architectural decisions and their reasoning are in
[docs/architecture.md](docs/architecture.md). What follows is only what that
document does not cover: how it got here, and what is uncertain.

## 2. The build process

One behavior at a time, red-green-refactor, through the public seams
(`luasec.api` or the CLI as a subprocess). One issue, one branch, one PR, with
disjoint file ownership between agents and the orchestrator merging. An
independent verifier reviewed every batch and its verdict blocked the merge.

Dozens of feature commits were merged this way, as numbered pull requests with
an independent verifier on each. The process worked: it found real defects that
no amount of my own testing had.

## 3. What verification found, in total

Nine independent review rounds, all returning DO NOT SHIP. Between them they
found, among others:

**Crashes that took down an entire scan.** Every one of these is a handful of
lines of ordinary Lua in a firmware tree, and every one produced a Lua
traceback, zero output, and every other file's findings discarded:

- `args[#index - 2]` where `#` binds tighter than `-` — the length of a number,
  on any method call whose receiver resolved to a function through a local.
- An operator's `-- luasec:` pattern handed to `string.match` with no guard. A
  one-character typo killed the scan — the same class of attack the lexical
  fallback exists to defeat.
- `cover_and_expose` testing an undefined global, always nil.
- `(value == nil) and false or value.tag` — Lua's `and/or` is not lazy in the
  middle, so a nil value was indexed. Fired on 4 of 562 real corpus files and
  replaced every secrets finding in the file with a low-severity "a rule failed
  to run". The run still exited 1, so CI stayed green.
- `linearize`/`name_functions` unprotected by the `pcall` that already wrapped
  the parser, so a duplicate `::label::` raised out of the CLI.

**Silent ground not covered.** Each of these reported a clean tree, or a clean
exit, for input that was never read:

- A directory that could not be read, treated as a directory with no Lua in it.
- `--max-nodes` and `--jobs` with a non-numeric value: a traceback with exit 1,
  which the tool defines as "findings". A CI with a typo in a variable got a
  security result.
- `--rules` pointing at a file that did not exist: stored as a string, iterated
  with `ipairs`, so `ipairs("profile.json")` ran zero times. The operator's
  declarations never loaded and the report came back narrower with a green exit.
- All symlinks, because `find -type f` matches the link rather than its target.
- `--only 70`, `--only 7`, `--only 70[0-9]` matching nothing, because the
  subject and the pattern were the wrong way round in the match call.
- `add_sources` appending the list as one element, so any source declared through
  the options table raised out of the public API.
- A `push`/`pop` region that was parsed and then never read, so a scoped
  suppression ran to end of file.
- A `-- luasec: only` whose pattern was a typo, which suppressed every finding
  in the file *and* the `012` that reports the typo.

**Precision.** Hardcoded-credential detection fired on 17 things that were not
secrets; narrowing it to zero drove out a rule that read CBI validator
expressions as credentials, and then a version that read any call ending in
`set` as a config write — `m.set("password", …)` on a plain Lua table.

**Correctness.** A byte order mark reported as a parse failure. `021` is
luacheck's code and was registered as ours. `plain` text silently written into a
`.json` file. A cross-file code flow rendering every step against the sink's
file.

## 4. The pattern, stated honestly

**Rounds 5, 6, 7 and 8 each ended with the previous round's fix as the blocker.**
Three times in a row I fixed a performance problem and introduced a correctness
or performance problem doing it:

| I did | What it broke |
| --- | --- |
| capped the list of values assigned to a table field at 8 | a cursor assigned as the *ninth* value was invisible, and a hardcoded credential written through it went unreported |
| capped a memo, and did not bound the fan-out of the walk | a 369-line file did not finish in 300 seconds |
| moved a depth-bounded but fan-out-unbounded recursion from a per-use site to a per-assignment pre-pass | an ordinary 40,000-line module took 28 s where it had taken 1.2 s |
| asked whether an assigned value was a `Call` rather than whether it was a cursor | six shapes that *store* a cursor went dark; six things that are not cursors became config writes |

The common mistake is the same each time: **capping something that should have
been summarised.** A cap is a guess about position. The questions here were never
about position.

## 5. Why the gate never caught any of it

This is the most important section in the document.

- **The corpus contains none of these shapes.** 562 real firmware files have
  almost no `X.uci = <cursor>` assignments, and the two there are assigned in
  place — so a rule that stopped recognising a *stored* cursor left every number
  in `docs/precision.md` exactly right. `747` measures **0** on this corpus
  whatever the rule does.
- **Over 570 specs all passed** through every one of these defects. The specs existed;
  they did not cover the shapes.
- **`make ci-verify` was green** while a file with a hardcoded root password in
  it reported clean, and while a 369-line file hung the analyzer.
- **`make precision` did not exist** for most of this. It was added in round 6
  and, until round 7, was not reachable in CI — the corpora are gitignored and no
  step cloned them, so the step took its skip path and printed `ci-verify: PASS`.

The measurement was the blind spot. A project that states a number and checks the
number is internally consistent is not measuring anything; it is checking that
two text files agree.

## 6. What was done about it

- `make precision` runs the analyzer over the corpora on every CI run and fails
  on any drift in the per-code breakdown, the total, or either file count. CI
  clones the corpora first and sets `PRECISION_REQUIRE_CORPUS=1`, so the step
  either measures or is red. It cannot pass without having looked.
- `test/spec/precision_golden_spec.lua` freezes the measured `(code, count)`
  pairs and checks the document against them **in both directions**, so a code
  added to the tool without a measurement, or a measurement edited without the
  tool, both fail.
- A skip path that prints `SKIPPED` three times and says in words that it is not
  evidence, rather than passing quietly.
- ~50 regression specs written for fixes that had shipped untested, each proven
  by reverting the fix in a scratch tree and watching it fail.
- A `make tdd-proof` that reverse-applies `src/` only and requires the new tests
  to fail.
- An adversarial suite that a verifier writes and that is kept as regressions.

## 7. Still open

Ordered by how much I would worry about it.

### 7.1 A field assigned a call that returns a cursor is not a cursor

```lua
local function open_section(name) return uci.cursor(nil, name) end
local t = {}
t.uci = open_section("system")
t.uci:set("system", "root_password", "Sup3rSecretPw")
```

Not reported. A factory whose name contains neither `uci` nor a trailing
`cursor` is invisible to the credential rule. This is the same direction as the
losses in section 4 — a credential that should be reported and is not — and it
is *known* rather than suspected. Fixing it means return-value flow inside the
secrets rule; return-value flow now exists for taint (section 7.2) but the
secrets rule does not use it yet.

### 7.2 No taint through a return value (fixed)

Fixed. PR #49 made taint follow the return value of a local function
(`local function id(x) return x end`), and PR #56 extended it to a module field
(`function M.id(x) return x end`, so `os.execute(M.id(io.read()))` reports 709)
and, under `--whole-program`, across files: `local u = require "util";
os.execute(u.id(io.read()))` reports 709 with the flag and 701 without it.

### 7.3 The measurement still cannot see the class of defect that has been most
common

Everything in section 4 is a shape real firmware may contain and this corpus
does not. The gate is now real, but its corpus is 562 files of upstream LuCI and
LuaJIT — not vendor firmware, not malicious input, not adversarial shapes.

**The fix I would make first** is a fuzz-and-budget gate: generated and
byte-mutated inputs with a wall-clock bound per case in CI, plus the specific
performance shapes as fixtures. That is the class of regression that has broken
this project four times, and nothing in the current gate would catch the fifth.

### 7.4 Bounds that are limits, not safety margins

- `MAX_CURSOR_HOPS = 6` and `MAX_CURSOR_DEFS = 4` in the credential rule's alias
  walk. Past those the answer is "not a cursor" and a credential can be missed.
- `MAX_WALK_PATHS = 50,000` per scan root. Beyond that the run reports a coverage
  gap. Correct behaviour, but a firmware image larger than 50,000 files needs
  `LUASEC_MAX_WALK_PATHS` set.
- `max_nodes` defaults to 20,000 and a file over it degrades to a forward pass
  and reports `904`. Deliberate, and reported.

### 7.5 A Lua pattern cannot be validated ahead of use

`string.match` and `string.gsub` compile a pattern as they walk, so a subject
that matches early never reaches the malformed part. Every probe tried — empty
subject, every byte value, anchored, `gsub` over a long subject — calls `70(`,
`70)` and `70%` valid, and in use they raise nothing either. Lua only objects
when the matcher actually reaches the broken token.

Consequence: those three forms in a *code* pattern produce no `012`, because
nothing ever discovers they are malformed. The fail-safe holds — a pattern that
cannot match matches nothing, so a broken suppression silences nothing rather
than everything — but the operator is not told. The name half of a
`code:name` pattern is worse: it is only evaluated when the code half matches,
so a malformed name on a code that matches nothing is never tried at all.

This is documented in the code and covered by a spec that asserts the achievable
contract rather than an unachievable one. It is a real gap in the diagnostics.

### 7.6 The depth array is positional where the version it replaced was
line-based

`directives.allows` is exported and the two disagree on an unsorted directive
list, in the fail-open direction. The lexer cannot produce one — it appends one
record per comment in token order — so it is not reachable through the CLI.
Noted rather than changed.

### 7.7 No review by anyone outside this process

Every one of the nine review rounds was run by an agent I dispatched, briefed by
me, using the same repository and the same understanding of what mattered. That
is genuine adversarial review — it found roughly thirty defects I had missed, and
it found them without my help — but it is not the same as a security researcher
who did not already believe the tool works. I would not represent it as one.

After the nine rounds, one further round ran with independent AI agents with no
part in writing the code, and its findings were fixed in PRs #61, #62, #63,
#68, #70, #71, #72, #73 and #74. That round was still AI review, not a human
outside the project.

## 8. What I am unsure about, in order

1. **Whether the remaining defects are narrow or systemic.** Nine rounds, each
   finding real problems, each fix introducing a new one. I genuinely do not know
   whether round 10 would find a blocker or a nit. The track record says to
   assume the former.

2. **Whether my own judgement here is a signal.** I introduced three of the four
   regressions in section 4. When the fix is mine and the review is mine, my
   assessment of "this is done" has been demonstrably wrong four times. I do not
   think I can be trusted to grade my own work in this codebase, and I would not
   accept my verdict as evidence.

3. **The precision number is reproducible but narrow.** 146 findings over 566
   files is a real, reproducible measurement of one corpus. It is not a measure
   of detection rate, and the corpus was chosen for being upstream LuCI, which is
   not the population this tool is for.

4. **The credential rule is the least-tested rule relative to its importance.**
   `747` has a hand-audited sample of 2 findings on the corpus, everything else
   measured by fixture. It is the rule that has produced the most false positives
   and the most false negatives in this project's history.

5. **Whether the platform profiles match real firmware closely enough.** The
   sources and sinks are declared by hand per platform. There is no measurement
   of how well they match what vendors actually ship, because that would need
   vendor firmware this project does not have.

6. **The payload validator's memory bound.** `SECURITY.md` documents the
   measurement, including that `/usr/bin/time -l` misreports its unit on macOS
   and that `getrusage` has two platform-specific traps. The reported resident
   set ranged 103 MB to 179 MB across batches on identical configuration — a
   1.7× spread inside one setup. A single sample is not a measurement of a
   distribution that wide.

## 9. If you are picking this up

Do these in order:

1. **Add the fuzz-and-budget gate** (7.3). It is the highest-value change
   available and it addresses the actual failure mode of this project.
2. **Grow the corpus** past upstream LuCI — vendor firmware images, and
   deliberately hostile ones. Every defect in section 4 is a shape the corpus
   does not contain.
3. **Implement return-value flow** (7.1, 7.2). It is the largest known coverage
   gap and it unblocks two separate findings.
4. **Get a review from someone who does not believe the tool works.** See 7.7.

The tool works today on the shapes it is measured on. Items 1 and 2 are what
would make that a stronger statement.
