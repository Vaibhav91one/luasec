# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased

Found by scanning public router firmware images unpacked to a rootfs.

- Progress on stderr while scanning: the files found, a live counter, and a
  closing count with the time. On by default only in a terminal; `--progress`
  and `--no-progress` override it, `--quiet` turns it off (#135).
- `--summary` prints counts by severity, confidence and code and the ten files
  with the most findings; a plain report of more than 100 findings ends with a
  hint that names it (#140).
- A raw firmware image or archive given as a file is one coverage finding that
  says what it looks like and to extract it first, not a lexical scan of its
  bytes that produced hundreds of bogus findings (#134).
- The score says `incomplete`, with the number of coverage gaps, instead of
  `good` when part of the input could not be analysed; JSON and SARIF carry
  `coverage_gaps` (#136).
- An extracted image's absolute symlinks are resolved against the image root
  instead of the machine running luasec; links to libraries and archives are not
  gaps, and the rest become one finding per scan root with a count. On one router
  image the coverage warnings fell from 238 to 19 (#137).
- A symlink to a file with a copy under the scanned root is no longer read
  from the host (#147).
- Colour follows the terminal (`NO_COLOR`, `--color`, `--no-color`), and
  progress on a terminal is a spinner with a bar and the current file (#156).
- On a terminal the default report is a grouped digest: score header with a
  bar, counts by severity and family, findings grouped by code worst-first;
  `--view list` keeps the flat list, `--verbose` shows everything (#157).
- `luasec why` prints a code frame around the reported line (#155).
- After a scan with findings on a terminal, an interactive menu offers
  explain, fix, all, save report, save baseline, CI, install guidance and
  quit; `--interactive` forces it, `--no-interactive` turns it off (#160).
- `--scope changed [--base <ref>] [--include-untracked]` scans only changed
  files, and `--staged` scans staged files for a pre-commit hook (#158, #163).
- `--category` keeps one or more code families, and
  `luasec rules set|enable|disable <code>` edits `luasec.config.lua` (#162).
- `luasec install --hook` writes a pre-commit hook that blocks on high
  severity at medium confidence or above (#161).

## 0.2.0 - 2026-09-30

- Health score and finding categories (#92).
- Score line at the end of the plain report, and `--score` (#95).
- Score in JSON and SARIF reports, and each result's category in SARIF (#94).
- Per-code doc pages with firing examples and fix prompts (#93).
- `luasec rules list` and `luasec rules explain <code>` (#96).
- `luasec why <file>:<line>` (#97).
- Project settings from `luasec.config.lua` (#91).
- `luasec fix`, handing findings to an AI coding agent (#98).
- `luasec install`, writing agent guidance into a project (#99).
- GitHub Action and `luasec ci install` (#100).
- LuaRocks rock `luasec-scanner` (#103).
- npm launcher, `npx luasec` (#108).
- Homebrew formula, release tarball and release workflow (#105).

### Fixed

- A 708 reported a byte offset in the file as its column, so SARIF pointed past
  the end of the line (#106).
- After a parse error, the lexical scan reported findings on the wrong line (#110).
- `luasec install` and `luasec ci install` created directories with Lua's `%q`,
  which is not shell quoting; a `--dir` containing `$(cmd)` ran `cmd` (#99, #100).
- The `fix` spec could launch a real agent installed on the test machine (#102).
- `luasec.config.lua` was executed (in an empty environment), so a config in a
  scanned tree could hang the run; it is now parsed as data. A numeric severity
  key was silently ignored and is now refused (#121).
- `luasec why` and `luasec fix` ignored `--only`, `--ignore`, the thresholds and
  the config file; they now select findings exactly as the scan does (#122).
- `luasec why` on a file it cannot read said nothing was reported; it now exits
  2. `--quiet --score` printed nothing on a clean tree (#114).
- `luasec install` overwrote a changed skill or Cursor rule; it now needs
  `--force` (#120).
- The action's score output was empty when `args` contained `-o`; it is read
  from the SARIF now (#119).
- Two concurrent first runs of `npx luasec` could fail on the cache rename (#113).

## 0.1.0

First release: the static analyzer, 37 rule codes, plain/JSON/SARIF/HTML
reports, baseline, bytecode triage and the payload validator.
