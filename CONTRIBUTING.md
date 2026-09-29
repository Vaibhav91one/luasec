# Contributing to luasec

- [How to start](#how-to-start)
- [Submit a PR](#submit-a-pr)
- [Adding a rule code](#adding-a-rule-code)
- [Other ways to help](#other-ways-to-help)

## How to start

Read [AGENTS.md](AGENTS.md) first. It is the single source of truth for how
work is done here, including the TDD discipline: one behavior, one failing
test, minimal code, pass — never a batch of tests then a batch of
implementation.

```sh
make lua vendor   # build the Lua interpreter and fetch pinned luacheck
make test         # run all specs
make adversarial  # run the adversarial regression suite
make selfscan     # scan src/ with luasec itself
make corpus       # clone the firmware corpora (network, gitignored)
make precision    # re-take the corpus measurement, after make corpus
```

`vendor/` is pinned — never modify it. `make vendor-verify` fails on any
drift.

## Submit a PR

- One issue = one branch `issue/<n>-<slug>` = one PR. The PR body starts
  with `Closes #<n>`.
- Follow [AGENTS.md](AGENTS.md): small diffs, public seams only in tests,
  behavior-stating test names.
- `make test` passes and `make tdd-proof BASE HEAD` shows the new tests
  failing without the change. A PR with no behavior change carries the
  `type:chore` or `type:docs` label, which skips the TDD proof.
- Squash merge. Do not merge your own PR. Never push to `main`, never create
  merge commits, never run `gh pr merge`.

## Adding a rule code

Every new warning code needs all four:

1. A registry entry in `src/luasec/rules/codes.lua` with CWE and severity.
2. A row in [docs/rules.md](docs/rules.md).
3. A page at `docs/rules/<code>.md` with a firing example, how to fix it,
   and a fix prompt (checked by `test/spec/rule_docs_spec.lua`).
4. A firing fixture and a silent fixture under `test/fixtures/`.

## Other ways to help

- Report a false positive or negative with a minimal Lua snippet that shows
  it — the smaller the snippet, the faster it becomes a fixture.
- Add a platform profile: a new `--std` file under
  `src/luasec/registry/stds/`, documented in
  [docs/firmware-stds.md](docs/firmware-stds.md).
- Improve a doc page. If a number in [README.md](README.md) stops being true,
  `test/spec/readme_spec.lua` fails the build — fix the doc, not the spec.
