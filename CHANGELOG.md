# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

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
- After a parse error, the lexical scan reported findings on the wrong line (#107).
- `luasec install` and `luasec ci install` created directories with Lua's `%q`,
  which is not shell quoting; a `--dir` containing `$(cmd)` ran `cmd` (#99, #100).
- The `fix` spec could launch a real agent installed on the test machine (#102).

## 0.1.0

First release: the static analyzer, 37 rule codes, plain/JSON/SARIF/HTML
reports, baseline, bytecode triage and the payload validator.
