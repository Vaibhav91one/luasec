# Reports

`lua-doctor` writes four formats. They are not four renderers over four shapes: every
one of them is rendered from the same normalized finding list
(`src/luasec/report/findings.lua`), so they cannot disagree about what a finding
is or in what order it appears.

| Flag | For | Notes |
| --- | --- | --- |
| `--format plain` | a terminal | the default |
| `--json` (`--format json`) | scripts, CI, a baseline | the `doctor/1` envelope, [docs/doctor-contract.md](doctor-contract.md) |
| `--format sarif`, or `--sarif FILE` beside any other output | a code scanning UI | SARIF 2.1.0, taint findings carry a `codeFlows` thread flow |
| `--format html` | a person, offline | one file, no external references |

## The finding contract

`--json` writes the shared `doctor/1` envelope, specified in
[docs/doctor-contract.md](doctor-contract.md) and identical across the doctor
tools: `schema`, `tool`, `version`, `exit_code`, `score`, `findings`, `data`, and
`baseline` under `--baseline`. A field outside the contract may change without
notice, and a consumer must ignore keys it does not know.

One lua-doctor finding in the envelope:

| Field | Type | Always present | Meaning |
| --- | --- | --- | --- |
| `id` | string | yes | the three-digit rule id (was `code`) |
| `fingerprint` | string | yes | 16 lowercase hex characters, see below |
| `severity` | string | yes | `critical`, `high`, `medium`, `low` |
| `confidence` | string | yes | `certain`, `high`, `medium`, `low` |
| `category` | string | yes | `exec`, `firmware`, `payload`, `artifact`, `meta` |
| `message` | string | yes | the human sentence, with `{name}` filled in |
| `location` | object | yes | `{kind, ref, line, column}`; `kind` is `file`, or `none` when `ref` is a directory nothing can open |
| `remedy` | string or null | yes | the first paragraph of the rule page's "How to fix" section; `null` when the page is not installed |
| `evidence` | array | no | `[{"ref": "snippet", "value": ...}]` when the finding has a snippet |
| `baseline_state` | string | with `--baseline` | `new` or `unchanged` |
| `cwe`, `name`, `sink`, `source`, `end_column` | | yes | lua-doctor extras: `""` rather than `null` when empty; `end_column` is one past the last column |
| `trace`, `sanitizer`, `guarded_by`, `channels`, `exposed_as` | | no | lua-doctor extras, present when they apply; `trace` is omitted when there is no proven flow |

What moved from the 0.5 document: `luasecVersion` is `version`, `reportVersion` is
`data.report_version`, `score.categories` is `data.categories`, `code` is `id`,
`file`/`line`/`column` are `location`, `snippet` is `evidence`, `status` is
`baseline_state` (and `fixed` findings are counted in `baseline.fixed`, not
listed). There is no legacy flag.

**The fingerprint** is the 64-bit FNV-1a hash of `code:name:file`, written as 16
lowercase hex characters. The line is not in it. It is the same value as SARIF
`partialFingerprints["doctorFinding/v1"]`.

Rules that make the JSON stable enough to diff and to key on:

- **Every string extra is always present, and is `""` rather than `null` when the
  finding has nothing to say there.** `remedy` is the one `null`, as the contract
  requires.
- **`trace` is omitted when the finding has no flow.** An empty array and an
  absent key mean different things: a finding with no proven path has no trace.

And one rule makes a report readable rather than merely well shaped:

- **No two findings in a report are identical in file, code, line, column,
  message and source.** The same sentence about the same place is one finding
  however many times an engine observed it, and the report says it once. It holds
  for every producer - `check_source`, `analyze`, `--jobs`, stdin, a baseline -
  because it is applied where the list is projected rather than in any one rule.
  It does *not* merge findings that differ in anything else: two exposures of one
  exported function naming different sinks, two taint findings at one sink from
  two sources, and the same code on two lines are all still separate rows.

A trace step is `{kind, line, name, file}`, where `kind` is `source`, `sink`, or a
propagation step. The order is **source first, sink last**, and that order is
guaranteed by the contract rather than by whatever order an engine happened to
produce them in.

The envelope's `score` is `{value, label, model, coverage_gaps}` with `model`
`"lua-doctor/1"`; the per-category counts are in `data.categories`. It is computed
from the findings, so the finding shape itself is unchanged. The `lua-doctor/1`
formula: the score is 100 minus, for each finding, its severity weight (critical
25, high 10, medium 4, low 1) times its confidence (certain or high 1, medium 0.6,
low 0.3), rounded down and floored at 0. Labels: `good` at 90 and above, `needs
work` at 60 and above, else `critical`. A coverage gap (any 901, 902, 904, 801,
803, 805 or 012 finding) turns "good" into "incomplete"; the number itself does
not change. A gap the baseline marked fixed is not counted.

## Determinism

Two runs over unchanged input produce byte-identical `--format json` output.
That is what makes the output diffable, and it is what the baseline mode is built
on. Two things make it true:

- **Key order is fixed.** Object keys are emitted in sorted order by
  `report/json.lua`, never in `pairs()` order, which is unspecified.
- **Finding order is a total order:** in the envelope `(severity, id, fingerprint,
  file, line, column, message)`, severity critical first, as the contract says; in
  `plain`, `sarif` and `html` `(file, line, column, code, name, message)`. So
  `--jobs 1`, `--jobs 8` and a different order of paths on the command line all
  produce the same bytes. Nothing in the report depends on the order the analyzer
  happened to visit files in.

`plain`, `sarif` and `html` share the second order.

### Strings round-trip

Any byte sequence that can appear in a finding survives `--format json` and
reading it back: double quotes, backslashes, tabs, newlines, control characters
and non-ASCII UTF-8. `report/json.lua` escapes what JSON requires and leaves
UTF-8 as UTF-8, and a spec parses the output back and compares byte for byte
against the input. A finding message is partly the analyzed file's own text, so
this is not a formality.

## SARIF

SARIF 2.1.0. `$schema` at the top level, `version: "2.1.0"`, one `run`.

**Every registered rule is declared.** `tool.driver.rules` carries one entry for
every code in `codes.all()`, so a `result.ruleId` always resolves. A code that
is reported but not declared is a finding a consumer cannot display.

**A taint finding carries a real code flow.** `codeFlows[0].threadFlows[0].locations`
is an array of objects, each with `location` and `executionOrder` counting from
1 with no gaps. The locations are in source-to-sink order: the source step first,
the sink last. Each step's `region.startLine` is that step's own line, and a
non-sink step's columns are not the sink's columns - a location that points at
the wrong text is worse than no location.

**Fingerprints.** `partialFingerprints` carries one key:

- `doctorFinding/v1` — the finding's fingerprint, a hash of code, name and file.
  **No line number.** This is the finding's identity, and a statement that moved down the file is the same finding, so a code
  scanning UI that keys on it does not report a known finding as new every time
  somebody inserts a comment.

`primaryLocationLineHash` is not written. It is GitHub's own hash of the source
line, GitHub computes it on upload, and an earlier lua-doctor wrote `code:name:line`
there, which GitHub answered with an "inconsistent fingerprint" warning on every
result (#311).

**Level.** `critical` and `high` are `error`, `medium` is `warning`, `low` is
`note`, whatever the confidence.

**Score and category.** The run carries `properties.score`, the same object as the envelope's `score`
(`value`, `label`, `model`, `coverage_gaps`), and each result carries `properties.category` with the finding's
category id. The plain Score line names the count (", 1 coverage gap").

### Validation

The output was validated against the official `sarif-schema-2.1.0.json` with
`jsonschema` (Draft 7 validator) over the whole fixture corpus, 156 results, and
it reported **0 errors**. The result is in the PR for this issue.

A spec also asserts the structural properties that a hand-rolled emitter gets
wrong, so `make test` catches a regression without a schema on disk:
`$schema` present, `runs` non-empty, every `result.ruleId` in `driver.rules`,
every thread flow location carrying `executionOrder` and a
`physicalLocation.artifactLocation.uri`, and no `null` where the schema wants a
value.

Two things the schema rejected during this work, both of which a reasonable
reading of SARIF would allow:

- a `message` on a `threadFlowLocation` — the schema forbids additional
  properties there. The step's own name goes in the location's region instead,
  and `importance` is used to mark the source and the sink.
- The emitter now writes a start column of `1` for a non-sink step rather than
  the sink's column, because the two are on different lines.

## Baseline mode

```sh
lua-doctor --json -o baseline.json src/                 # record
lua-doctor --baseline baseline.json src/                # what is new since then
lua-doctor --json --baseline baseline.json -o baseline.json src/   # accept the fixes
```

The baseline is a previous `--json` envelope, matched by `fingerprint` only
(a hash of `code`, `name` and `file`); an old 0.5 report is refused with exit 2.
There is deliberately no line number. A baseline keyed on line numbers reports
every finding as new the moment somebody inserts a comment above it, and a gate
that cries wolf is a gate people turn off.

A finding is one of three things:

| | In the baseline | In this run | Reported | Fails the build |
| --- | --- | --- | --- | --- |
| **new** | no | yes | yes | yes, if at or above `--fail-on` |
| **unchanged** | yes | yes | no in plain; yes in `--json` as `unchanged` | no |
| **fixed** | yes | no | yes in plain/html/SARIF; in `--json` only counted in `baseline.fixed` | no |

Only `new` findings fail a build. A fixed finding is reported because "the thing
you were tracking is no longer there" is worth knowing, and it never costs
anybody a green pipeline.

**A finding that moved lines is not new.** Its fingerprint has no line in it.

**A finding whose code changed is new**, even at the same place on the same line
in the same file. A 701 that became a 709 is a different claim about the code and
has to be looked at.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | clean, or nothing new under a baseline |
| 1 | findings at or above `--fail-on`, no baseline in play |
| 2 | error: unreadable input, or a baseline that is not a `doctor/1` envelope |
| 130 | interrupted |
| 3 | `--baseline` only: at least one **new** finding at or above `--fail-on` |

A separate code rather than reusing 1 is what lets a build script say "fail only
if something is new" without parsing the report. A baseline that cannot be read
or is not a lua-doctor report exits **2**, not 0: a mistyped path must stop the run,
not silently turn the gate off.

Under `--json --baseline` the envelope lists the whole run: every finding with
`baseline_state` `new` or `unchanged`, plus `baseline: {new, unchanged, fixed}`.
So its own output is a valid next baseline, and the `score` is the score of the
whole tree. The other formats keep listing only what changed. A new finding takes
precedence over a coverage gap in the exit code (3 over 1); a run with a coverage
gap and nothing new still exits 1, because a baseline never suppresses a gap.

## HTML report

One file. No `<script>`, no `<link>`, no `<iframe>`, no `<img>`, no `src=`, no
`href=`, no `@import`, no CSS `url()`. Styling is inline. The report opens on a
machine with no network, which is usually the machine the firmware came off.

Findings are **grouped by severity**, worst first, each group under a heading with
its count, and a pill row of counts at the top. A reviewer opens this to answer
"is anything critical", and a critical finding in the middle of a 156-row table is
a critical finding nobody reads.

A taint finding shows its **flow as source → sink**, each step naming the file and
line it is on, so the claim "untrusted data reaches command execution" comes with
the lines that make it.

The **code, the CWE and the confidence** are on every row, next to the file,
line and column.

**Everything is escaped.** `&`, `<`, `>`, `"` and `'` become entities in every
field that comes from an analyzed file: the message, the file name, the snippet,
the CWE, the trace step names. A scanned file is untrusted input, and a report
that pastes a message into a page unescaped turns a scanned file into script
running in the reviewer's browser. A spec renders a finding whose message
contains `<script>alert(1)</script>` and asserts the output has `&lt;script&gt;`
and no live `<script>`.

A fixed finding is shown, badged `fixed` and struck through. It is history, and it
must not read as a live problem.

## What is not in the contract

- **No timing, no environment, no hostname.** A report records findings, not the
  machine that made them, so two reports of the same tree compare equal.
- **No finding id that a consumer must trust across versions.** The fingerprint
  is deliberately simple and documented; it is not a hash and makes no
  collision-resistance claim.
- **No `sarif-tools` / `ajv` dependency.** The schema validation was performed
  once, offline, and the result is in the PR. The specs carry the structural
  properties so the suite needs no network and no extra tooling.
