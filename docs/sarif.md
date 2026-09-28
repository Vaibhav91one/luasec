# Reports

`luasec` writes four formats. They are not four renderers over four shapes: every
one of them is rendered from the same normalized finding list
(`src/luasec/report/findings.lua`), so they cannot disagree about what a finding
is or in what order it appears.

| Flag | For | Notes |
| --- | --- | --- |
| `--format plain` | a terminal | the default |
| `--format json` | scripts, CI, a baseline | the stable machine contract |
| `--format sarif` | a code scanning UI | SARIF 2.1.0, taint findings carry a `codeFlows` thread flow |
| `--format html` | a person, offline | one file, no external references |

## The finding contract

One finding, in every format, has these fields and no others. A field that is
not on this list is not part of the contract and may change without notice.

| Field | Type | Always present | Meaning |
| --- | --- | --- | --- |
| `code` | string | yes | the three-digit rule id |
| `severity` | string | yes | `critical`, `high`, `medium`, `low` |
| `confidence` | string | yes | `certain`, `high`, `medium`, `low` |
| `cwe` | string | yes | e.g. `CWE-78`; `CWE-0` when no CWE applies |
| `message` | string | yes | the human sentence, with `{name}` filled in |
| `name` | string | yes | what was reported, e.g. `os.execute` |
| `sink` | string | yes | the sink path; `""` when the finding is not a flow |
| `source` | string | yes | the untrusted input; `""` when the finding is not a flow |
| `file` | string | yes | the analyzed path |
| `line` | number | yes | 1-based |
| `column` | number | yes | 1-based |
| `end_column` | number | yes | one past the last column |
| `trace` | array | no | the source-to-sink path; absent when there is none |
| `status` | string | no | `new` or `fixed`; only ever present under `--baseline` |

Two rules make the JSON stable enough to diff and to key on:

- **Every string field is always present, and is `""` rather than `null` when the
  finding has nothing to say there.** A consumer never has to ask whether a key
  is missing or merely empty, and a serializer never has to invent a `null`.
- **`trace` is the one key that is omitted when the finding has no flow.** An
  empty array and an absent key mean different things: a finding with no proven
  path has no trace, and writing `[]` would suggest the analysis looked and found
  an empty flow.

A trace step is `{kind, line, name}`, where `kind` is `source`, `sink`, or a
propagation step. The order is **source first, sink last**, and that order is
guaranteed by the contract rather than by whatever order an engine happened to
produce them in.

## Determinism

Two runs over unchanged input produce byte-identical `--format json` output.
That is what makes the output diffable, and it is what the baseline mode is built
on. Two things make it true:

- **Key order is fixed.** Object keys are emitted in sorted order by
  `report/json.lua`, never in `pairs()` order, which is unspecified.
- **Finding order is a total order:** `(file, line, column, code, name,
  message)`, with a leading `status` when a baseline run is marking findings. So
  `--jobs 1`, `--jobs 8` and a different order of paths on the command line all
  produce the same bytes. Nothing in the report depends on the order the analyzer
  happened to visit files in.

`plain`, `sarif` and `html` inherit the same order.

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

**Fingerprints.** `partialFingerprints` carries two keys:

- `primaryLocationLineHash` — code, name and line. It is the key the SARIF
  vocabulary suggests, and it moves with the line.
- `luasecFinding` — code, name and file. **No line number.** This is the finding's
  identity, and a statement that moved down the file is the same finding. Both
  are emitted because the standard key cannot be stable under a line move, and a
  code scanning UI that keys on it would report a known finding as new every time
  somebody inserts a comment.

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
luasec --format json -o baseline.json src/          # record
luasec --baseline baseline.json src/                # what is new since then
luasec --baseline baseline.json -o baseline.json src/   # accept the fixes
```

The unit of comparison is a finding's **fingerprint**: `code`, `name` and `file`.
There is deliberately no line number. A baseline keyed on line numbers reports
every finding as new the moment somebody inserts a comment above it, and a gate
that cries wolf is a gate people turn off.

A finding is one of three things:

| | In the baseline | In this run | Reported | Fails the build |
| --- | --- | --- | --- | --- |
| **new** | no | yes | yes | yes, if at or above `--fail-on` |
| **known** | yes | yes | no | no |
| **fixed** | yes | no | yes, as `status: "fixed"` | no |

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
| 2 | error: unreadable input, or a baseline that is not a luasec report |
| 3 | `--baseline` only: at least one **new** finding at or above `--fail-on` |

A separate code rather than reusing 1 is what lets a build script say "fail only
if something is new" without parsing the report. A baseline that cannot be read
or is not a luasec report exits **2**, not 0: a mistyped path must stop the run,
not silently turn the gate off.

The baseline is a plain `--format json` report. It is *not* the output of a
baseline run: a baseline run reports only what changed, so feeding its own output
back in would forget everything it did not report. Regenerate it with a plain
run.

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
