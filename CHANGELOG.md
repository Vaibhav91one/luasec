# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## 0.6.1 - 2026-10-10

- Renamed: the tool is now **Lua Doctor**, `lua-doctor` (was `luasec`). This is a breaking rename for every user-facing name: the command (`bin/lua-doctor`; no `luasec` alias is kept), the npm package (`@doctor-labs/lua-doctor`; the unscoped npm name is taken by another project, the command stays `lua-doctor`), the rock (`lua-doctor`, was `luasec-scanner`), the Homebrew formula, the GitHub Action (`doctor-labs/lua-doctor`), the `doctor/1` envelope `tool` field and `score.model` (`lua-doctor/1`), the config file (`lua-doctor.config.lua`), the environment variables (`LUA_DOCTOR_*`, was `LUASEC_*`), the SARIF `partialFingerprints.luaDoctorFinding` key, the yara pack (`yara/lua_doctor_signatures.yar`, rule names `lua_doctor_sig_*`), the installed skill, Cursor rule and AGENTS.md markers, and the cache directory (`~/.cache/lua-doctor`). The in-source directive is `-- lua-doctor: ignore ...`; the old `-- luasec: ignore ...` spelling is still honoured. Repository links point to `https://github.com/doctor-labs/lua-doctor`. The Lua module namespace is renamed too: `require "luasec.api"` is now `require "luadoctor.api"` (sources in `src/luadoctor/`). Not published yet: the next release publishes `@doctor-labs/lua-doctor` and deprecates the old `luasec` package.

- 722: a value written through a UCI cursor handle (`c:set(...)`, `c:section(...)`, `c:tset(...)`, `add_list`, `set_list`) is reported when request data reaches it (#317). A constant or merely computed value is not reported, and neither is a tainted section or config name; the literal `uci.set` form is unchanged. The handle tracking of rule 747 moved to `src/lua-doctor/util/uci_cursor.lua` so the dataflow pass shares it (a per-file state, so the engine can switch between files). A cursor factory defined in another file is not followed, also under `--whole-program`: that pass carries taint, not a "returns a handle" fact, and handle tracking is a per-file walk with its own memo, so it would need a cross-file resolver inside that walk. Documented in the README limits. New `test/spec/cursor_write_spec.lua`.
- Corpus: 620 -> 670 findings, all 50 new ones 722 in `luci-1806` (the current `luci` entry has none), each a tainted flow checked with `lua-doctor why`; no other code moves. README severity row 554 high (was 504).
- lua-doctor reads Lua out of an nginx.conf (#296): the bodies of `*_by_lua_block { ... }` are scanned with the `openresty` profile added to `--std`, and a finding lands on the `.conf` line and column. The walk selects a `.conf` only when it holds such a block; `content_by_lua '...'` strings and `*_by_lua_file` are not read (the file a `_file` directive names is scanned as itself). New `src/lua-doctor/cli/nginxconf.lua`, `test/spec/nginxconf_spec.lua`.
- Corpus: the authored `openresty-authored/nginx.conf` (15 handlers) is now a pinned corpus entry, copied by `clone-corpus.sh` and diffed by `--verify`. 610 -> 620 findings over 707 files (was 706): 701 45 -> 46, 709 29 -> 34, 728 1 -> 2, 730 absent -> 3, all ten in that one file and each named in docs/precision.md (8 intended, 2 known false positives). Everything else unchanged.
- Taint follows a table the code fills (#317, #309). `t[#t+1] = v`, `t[k] = v` and `table.insert(t, v)` taint the variable that holds `t`, a `for k, v in ipairs(t)` loop's names carry what they iterate (`ipairs` and `pairs` are propagators), and a table used as a whole (`table.concat(t, " ")`, `return t`, an argument) carries everything written to its fields. A named field read stays exact: `t.safe` is not tainted by `t.cmd = x`. A function that builds and returns a table is summarised under each call's own arguments, so `parse("fixed").path` stays clean next to `parse(x).path`. Bound: a whole-table read is answered once per table per propagation round (no re-expansion of tables that store each other, 60 stacked tables in a spec) and the usual 20-round propagation cap applies; there is no per-slot model of an array, so a constant `t[1]` read from a table whose `t[2]` was tainted is tainted too.
- Call sites nested in another call's arguments (`ipairs(parse(x))`, `os.execute(run(x))`) now bind the callee's parameters, and a trailing `...` fills every remaining formal there as it already did in a followed return. The string methods `byte sub gsub gmatch match lower upper rep reverse` pass their receiver's taint like `string.*`, and `unpack`, `table.unpack`, `luci.http.urldecode` are propagators.
- 747: a function that returns `uci.cursor()` is a config handle, so a credential written through `open_section():set(...)` or `local c = open_section(); c:set(...)` is reported. A local, a global and a same-file `M.name` factory are followed, newest definitions first, at most 4 returns each and the existing 6-hop limit; another library's `cursor()` and a factory returning a plain table are not handles. The README no longer lists this as a limit (it still lists a factory in another file).
- Corpus: 610 findings, unchanged in total; 701 46 -> 45, 702 14 -> 13, 703 20 -> 19, 709 27 -> 29, 710 1 -> 2. `commands.lua:163` and `:220` are 709 (were 701/702 at low); `luajit/src/host/genlibbc.lua:145` is a 710 (was a 703). `ddns/detail.lua:439`, `:867` and `:918` reach `DDNS.parse_url` in another file, so they become 709 under `--whole-program` only (nothing else in the corpus moves there); a default scan still reports them as 701. README severity row corrected to the measured 31 critical, 500 high, 34 medium, 45 low.
- The luci std declares LuCI CBI request data: the `formvalue` and `formvaluetable` methods on any receiver (`ip:formvalue(section)`), and the `value` argument of `validate` and `write` callbacks in a `model/cbi/` file. A value from them reaching `luci.sys.call` or `os.execute` is a 709, not a 701/708 at low confidence. A method source no longer overrides a declared dotted path (`luci.http.formvalue` keeps its id and `certain`).
- A trailing `...` in a call now fills every remaining parameter of a local function (`helper(...)` feeds `helper`'s second formal too), so a dispatcher's URL segments forwarded through `...` reach a sink in the helper.
- Corpus: 611 -> 610 findings; 701 50 -> 46, 708 22 -> 21, 709 23 -> 27. Still 701 on `ddns/detail.lua:439`, `:867`, `:918` (the value goes through `DDNS.parse_url` in another module and a field read) and `commands.lua:163` (the argument is appended to a table with `argv[#argv+1] = v`, which taint does not follow) (#309, part).

## 0.6.0 - 2026-10-09

Breaking: the JSON report is now the shared `doctor/1` envelope ([docs/doctor-contract.md](docs/doctor-contract.md)), the same contract the other doctor tools write. The old shape is gone, with no legacy flag.

- `--json` (alias of `--format json`) prints `{schema: "doctor/1", tool, version, exit_code, score, findings, data}`. Per finding: `code` is `id`; `file`/`line`/`column` are `location`; `snippet` is `evidence`; new `fingerprint` (16 hex), `category` and `remedy` (the rule page's "How to fix", or `null`); `cwe`, `name`, `sink`, `source`, `end_column`, `trace` and the rest stay as extra keys. `luasecVersion` is `version`, `reportVersion` and the per-category counts moved under `data`. Findings are ordered by severity, then id, then fingerprint (#316).
- `score` is `{value, label, model: "luasec/1", coverage_gaps}`; the formula is unchanged. SARIF `properties.score` has the same shape, and `action.yml` still reads `.value`.
- `--baseline` takes a `doctor/1` envelope and matches by `fingerprint`; a baseline from 0.5.x is refused with exit 2. `--json --baseline` lists every finding with `baseline_state` `new` or `unchanged` and adds `baseline: {new, unchanged, fixed}`; fixed findings are counted there, not listed. A new finding now takes precedence over a coverage gap (exit 3, not 1).
- SARIF: `partialFingerprints.luasecFinding` is now `partialFingerprints["doctorFinding/v1"]` with the 16-hex fingerprint, `--sarif FILE` writes SARIF beside any other output, and `critical`/`high` are always `error` (a low-confidence one used to be a `warning`).
- `--fail-on info` is accepted (below every severity luasec emits, so it fails on any finding).
- New `luasec mcp`: an MCP server on stdio with one tool, `scan`, that returns the `--json` envelope byte for byte. Which flags it leaves out is in the README.
- Human renderers (plain, the doctor view, `--summary`, `why`, the validator report) escape C0/C1 controls, bidi controls, zero-width characters and line separators in text taken from the scanned file, through one helper, `util.sanitize`. A scanned file could put an ESC sequence into a finding message and have it reach the terminal.
- `json.encode(value, false)` no longer collapses runs of whitespace inside strings.
- #316 ("no CLI scanner and no structured output") was filed when luasec was a library only; `bin/luasec` and `--format json` already existed. What it asked for that applies is the stable structured format and documented exit codes, which this release makes a shared contract.

## 0.5.1 - 2026-10-07

- The `shell-quoted` sanitizer label is only attached to an exec sink. It was set for every wholly-quoted flow while the confidence discount was already exec-only, so a quoted value reaching `loadstring` (710) was labelled `shell-quoted` (#303).
- luaposix's execution calls are declared from the library's own source (v36.3), not guessed: `posix.exec`, `posix.execp`, `posix.unistd.exec`, `posix.unistd.execp`, `posix.execx`, `posix.spawn`, `posix.popen` and `posix.popen_pipeline`, with the argument positions the source shows (there is no shell form; the deprecated `posix.exec(path, ...)` takes the argv as a table or as strings, so the `sh -c` command is argument 3). `posix.exec.*` matched nothing and is removed (#297, #278).
- A tainted `ngx.re.find` / `ngx.re.gsub` pattern is reported as 728 only. It was also reported as 709 "command execution" at certain confidence for an API that executes nothing (#310).
- SARIF no longer writes `partialFingerprints.primaryLocationLineHash`: it is GitHub's own hash of the source line, and the value luasec put there (`709:os.execute:2`) made GitHub log an "inconsistent fingerprint" warning on every result of every upload. `luasecFinding`, the stable identity, is unchanged (#311).
- An authored OpenResty `nginx.conf` of fifteen request handlers is measured by `test/spec/openresty_authored_spec.lua` (8 reported as intended, 4 silent as intended, 1 missed, 2 reported although safe), and `docs/precision.md` says what it stands in for and what it does not. It is outside `corpus/` and the golden, which did not move (#296, part).

## 0.5.0 - 2026-10-06

- A wholly shell-quoted command is still reported, one confidence step lower. When every tainted part of an exec-sink argument went through a shell-quoting helper, the 709 now reports at one step below the same flow unquoted (certain to high) with `sanitizer: shell-quoted` kept on the finding and the severity unchanged; a partly quoted command still gets a 712 and keeps full strength. Only exec sinks: quoting does nothing for `loadstring` (710) or a header, so those keep their confidence. `docs/rules/709.md` now says so. Counts do not move (#287, #230).
- A local that held something untrusted and was then overwritten with a constant is that constant at the sink, so the 701 (non-constant argument) no longer fires for it. The fold uses the one definition that reaches the use, only when the variable was declared with a value and no closure also writes it; a use with several reaching definitions (a branch, a loop, a closure write) keeps reporting. Over the pinned LuCI applications the platform profile now adds proven flows: 709 goes from 2 to 9 with `--std +openwrt+luci+luajit` and stays at 2 without it (#229, #237).
- An `entry_points` file glob is matched on the normalised path: `.` and `..` segments are folded out before `*/controller/*.lua` is tested, so `controller/../other/x.lua` no longer matches by its text while resolving elsewhere. `*` still crosses `/`, so nested controllers keep matching, and `docs/firmware-stds.md` says exactly that (#248).
- The dead `luci.util.uci.*` 722 sink (an alias only in LuCI 17.01 and earlier) is removed from the `openwrt` and `luci` stds, with a spec that the alias reports no 722; corpus counts are unchanged (#278).
- 747 no longer treats a test fixture or a protocol default as an exposure: such a hit is reported low (#295).
- `make ci-verify` no longer prints PASS when the corpus measurement was skipped: it exits non-zero with `INCOMPLETE` when `corpus/` is absent (#233). The README's per-code count rows are gone and the rule that keeps them out is enforced (#293); a spec pins that each rule page's documented confidence matches the emitted one (#231).
- Argument binding follows calls that are not whole statements and resolves global callees, and a call's arguments bind to the callee's own vararg with the hop's cost decided (#281, #283, #286). A declared source is resolved when it is read, not only when it is called, which revives the `ngx.var.*` family (#252). A global `function` statement is read as the definition it is (#264).
- New sinks and forms: the OpenResty HTTP-message writes (730, 731) (#239), `ngx.header[k] = v` as a target sink (#267), both calling forms of `nixio.exec` and `nixio.execp`/`nixio.exece` (#269, #276), and a dynamic-code sink reached through an alias is no longer silent (#275).
- Precision: 741 reads a shadowed `load` by what its definition does and what a `gsub` substitution produces (#254, #271); 724 is downgraded for an exposed handler whose command is a literal (#263); a local whose only definition is a constant folds (#250); a SARIF result names a file a consumer can open, or names nothing (#257); a dangling runtime-state symlink is not a coverage gap (#242); the walker stops selecting files that are not Lua (#292).
- The corpus gains pinned OpenResty Lua and is verified before it is measured (#289); the whole-program memory bound is absolute and taken in a fresh process (#259); `src/` is linted with the vendored luacheck and a spec checks that loading a module adds nothing to `_G` (#282).
- A report no longer publishes the same finding twice. An exported function reaching several execution sinks produced one 708 per exposure, all written at the function's own line, so `luci-app-splash`'s `splash.lua:105` printed four times over with nothing to tell the copies apart. `findings.normalize` now publishes each distinct finding once, so the property holds for every producer — `check_source`, `analyze`, `--jobs`, stdin and a baseline — rather than for one rule. Findings differing in `file`, `code`, `line`, `column`, `message` or `source` are never merged, so two exposures naming different sinks, two sources into one sink and the same code on two lines all still stand, and each exposed sink remains reported as a 701 at its own line. Over the firmware corpora this takes 708 from 32 to 24 and the total from 253 to 245, with every other code byte-identical (#261).
- 708 no longer replaces the 701 at the sink it names. An exported function whose execution sink is fed by something the file cannot fold was reported once, as a 708, and the sink itself got nothing. The exposure pass and the shape-only pass shared one "already reported" table, so the 708 suppressed the 701 at its own sink; the 708 message now says whose argument is unfed rather than naming the sink, and both findings stand. Over the firmware corpora this restores 29 findings at 701 and 4 at 704 — including `luci-app-lxc/controller/lxc.lua:70`, six dispatcher-supplied arguments interpolated into a shell command with no quoting. No file that was clean became dirty, and 708 itself is unmoved (#225).
- The `luci` std models how a LuCI handler actually receives input. `luci.dispatcher` resolves `/admin/luci/<module>/<action>/<segment>...` and calls the controller module's exported function as `stem_action(node, <every URL segment>)`, so every argument in a file under `controller/` — including the vararg of a `function(...)` handler — is declared as an entry point at `medium` confidence. Over `corpus/` this takes 709 from 5 to 17, and the weaker shape-only and exposed-sink findings those sites carried are no longer reported beside them (708 36 to 33, 724 28 to 25, 701 25 to 22, 702 21 to 15; two more sites now show their partial quoting, 712 1 to 3). `luci.http.getenv` — how a handler reads `REMOTE_ADDR` and the `HTTP_*` headers — is a source at `certain` (#226).
- An `entry_points` entry may use `arg = "*"` for "every parameter, and the vararg", for a dispatcher whose arity is the request path rather than the signature. A `...` has no parameter position to list, so a handler written `function(...)` was untainted however long a position list was (#226).

## 0.4.0 - 2026-10-03

- A profile may declare `validators` (an IP/host/number check used as a guard). A command flow guarded by one is kept but reported one confidence step lower with a `guarded_by` field and a message note, instead of at full confidence: a static pass cannot prove the check rejects every metacharacter, so the judgement is left to a reviewer or the `fix` agent. The cgilua std declares the CGILua IP/host validators (#218).
- A finding records which channel reaches the sink. An entry-point or source declaration may carry a `channel` tag (`web`, `acs`, `cli`, ...); a 709/729 then shows `[reachable from: ...]` and carries a `channels` array in JSON/SARIF. A file-scoped entry point now beats a global one of the same name. The cgilua std tags its web sources `web`, the TR-069 diagnostics handlers `acs`, and the CLI ping handler `cli` (#217).
- 729 is column-accurate: a value read back from a whole row narrows to the column the sink actually uses, and a row write records the columns it actually sets, so a writer of one column no longer pairs with readers of the rest of the table. On one firmware image this cut 729 from 121 to 39 (#215).
- New rule 729: request data written to a declared store and read back into a command, paired by table and column across the whole scan (no `--whole-program` needed). A profile declares `store_writes` and `store_reads`; the cgilua std declares the `db.*` API. A paired read replaces the 701/702 at that site; a scan with no tainted write reports what it did before (#211).
- Under `--whole-program`, a method call across files is followed like the dotted call it stands for: `mod:run(req)` into `function M:run(cfg)` or `M.run = function(self, cfg)` in a required module, and `gui.net:set(t)` into a global table's method in another file, the receiver binding to `self` (#210).
- The file walk runs one `find` per scan root instead of three (files, unreadable directories, links), with the same file list and coverage gaps: over `corpus/` it takes 1.1-1.2s instead of 2.0-2.2s, most of the saving system time (#205).

## 0.3.0 - 2026-10-03

- `--whole-program` peak memory over `corpus/` is down from about 270MB to about 190MB, with the same report and CPU time: the collector runs sooner while every file's syntax tree is held for the cross-file pass (#197).
- Under `--whole-program`, a call through a route table (`handlers[name](req)`, `routes[name].handler(req)`) with a key known only at run time is followed into every handler in another file that the table literal names; at most 64 per call, past which a 904 says the bound was hit (#193).
- An `entry_points` entry can carry `file`, a path glob: it then applies only to functions in matching files, so a profile can say "every function in `*/easyMesh*.lua`". Name-only entries are unchanged, and a `file` entry never matches `check_source`, which has no path (#192).
- `--jobs N` now analyzes files in N worker processes (it was accepted and ignored). The report is the same bytes as a one-process run in every format; a worker that dies has its slice analyzed in the main process; `--whole-program` stays in one process. Over `corpus/` on a loaded 10-core machine, `--jobs 8` took 4.5-4.7s against 6.5-7.1s for `--jobs 1` (#196).
Found by scanning public router firmware images unpacked to a rootfs.

- A profile can declare `entry_points` (function name pattern and argument positions): those arguments start tainted, so a sink they reach is a 709 instead of a 708. The cgilua std declares `*Handler` (argument 1) for the mesh JSON-RPC handlers (#178).
- Under `--whole-program`, a call to a dotted global function defined in another file (`gui.a.b.set(t)` with `function gui.a.b.set(cfg)` elsewhere) binds its arguments to that function's parameters, for a statement call and for one whose result is assigned. A name defined in two files is not guessed, and a local root is not the global (#179).
- A file that failed to parse only because a string held an escape Lua 5.1 accepts (`"\/"`, `'\.'`) is parsed again with that escape rewritten to one of the same length, so its flows are analysed instead of falling back to a 901 (#181).
- A sink entry can carry `filters` (argument position to the characters its callee strips). A flow into a partly filtered argument is still reported, one confidence step lower, and the message names what is removed and what still passes; the cgilua std uses it for `util.runShellCmd` and `util.shellCmdOutput` and now reports a tainted `options` argument at full confidence (#177).
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
- The doctor score header is a boxed panel with the score, a block bar and the
  counts, and progress names the file-finding and report-building phases; the
  closing progress line says `Scanned` (#166).
- The interactive menu opens with a findings browser: a cursor list grouped
  by category with a detail pane per finding (why, evidence, fix) (#167).
- The menu is an arrow-key picker that marks one state-aware recommendation
  (review for critical or high findings, saving a report otherwise), and `f`
  hands the findings to an agent submenu: pick an installed agent (approvals
  always on), copy the fix prompt (pbcopy, wl-copy, xclip, xsel, else OSC 52)
  or show it (#168).
- `--std cgilua` for CGILua web backends: the global `cgi` request table,
  `RowId`, `DBTable` and `NextPage`, `web.cgiToLuaTable` and its helpers as
  sources, and the vendor wrappers `util.runShellCmd` and
  `util.shellCmdOutput` as exec sinks (#176).
- The findings browser and the picker fit every row to the terminal width
  (middle-ellipsis, `file:line` tail kept for paths) and wrap detail text at
  word boundaries, so narrow terminals no longer wrap rows and drift the
  redraws (#174).
- CGILua pages are scanned by their Lua blocks: `.html`/`.htm` by `<?lua`
  ... `?>` (a walk collects a page that holds one), `.lp` by those forms and
  by `<%` ... `%>` / `<%=` ... `%>` when named explicitly (LuCI's `<%:`
  dialect pages hold no block and are skipped). The HTML is blanked but the
  lines and columns are kept, so a finding lands on the page's own line;
  a page with no block is skipped (#175).

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
