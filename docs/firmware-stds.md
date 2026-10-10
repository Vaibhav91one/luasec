# Firmware standards: the path and mode tables

`src/luadoctor/rules/firmware.lua` owns codes 721 to 728. Everything it matches
against lives in four tables at the top of that file, not scattered through the
detectors, so a vendor can read the whole set at once and extend it without
touching matching code. This file explains what the tables mean and why the
matching is built the way it is.

## The four path sets

| Table | Used by | What belongs in it |
| --- | --- | --- |
| `FLASH_PATHS` | 721 | Flash devices and kernel tunables: `/dev/mtd*`, `/dev/ubi*`, `/dev/nvram`, `/proc/sys/*` |
| `FIRMWARE_CONFIG_PATHS` | 721, 726 | Files a boot-time service reads and the ones that decide what it runs: `/etc/config/*`, `/etc/init.d/*`, `/etc/rc.local`, `/etc/uci-defaults/*` |
| `SENSITIVE_READ_PATHS` | 723 | Credentials and process state: `/etc/shadow`, `/proc/self/environ`, `/proc/<pid>/cmdline`, `*/id_rsa*`, `*.pem`, `*.key`, `*.p12`, `/etc/ssl/private/*` |
| `PROTECTED_PATHS` | 726 | Paths a script has no business removing or renaming: `/etc/init.d/*`, `/usr/bin/`, `/etc/rc.local` |

`/etc/passwd` is deliberately absent from `SENSITIVE_READ_PATHS`. It is world
readable on a stock device, so reading it is not the bug reading `/etc/shadow` is,
and a set that flags it flags a large share of ordinary firmware scripts.

### Fields a set may use

Every field is optional.

| Field | Test |
| --- | --- |
| `exact` | the whole path equals the string |
| `prefixes` | the path begins with the string, compared at offset 1 |
| `segment_match` | `count` = the number of `/`-separated segments, `at` = `{{index, literal}, ...}` |
| `basename_prefixes` | the last segment begins with the string |
| `basename_suffixes` | the last segment ends with the string |

Segments count the empty segment a leading `/` produces, so `index` 1 is that
empty segment and `/proc/1/cmdline` is `count = 4` with `{4, "cmdline"}`.

### Why nothing here is a Lua pattern

A path is compared, never matched. `exact` and `prefixes` are string
comparisons, `segment_match` counts separators with a plain `find`, and the
basename tests compare the ends of a segment.

That is a security property, not a style choice:

- **A path that contains the text of an entry is not the entry.**
  `/tmp/etc/config/network` does not start with `/etc/config/`, and
  `/tmp/myshadowfile.txt` is not `/etc/shadow`. A `find` with the entry as a
  needle would report both, and firmware scripts use `/tmp` for scratch files
  constantly.
- **No input can make the matcher backtrack.** Every test costs time
  proportional to the length of the path with a bounded constant, so a path of
  a megabyte of `a` costs a megabyte of work, not a megabyte squared. This
  matters because the path is attacker-influenced text in exactly the cases that
  matter.

Both cases are in `test/spec/firmware_spec.lua` as silent fixtures.

## The mode table

The mode string is C's `fopen` contract, which Lua passes through unchanged.

| Mode | Read | Write | Truncates |
| --- | --- | --- | --- |
| absent | yes | no | no |
| `r`, `rb` | yes | no | no |
| `w`, `wb` | no | yes | yes |
| `a`, `ab` | no | yes | no |
| `r+` | yes | yes | no |
| `w+` | no | yes | yes |

A missing mode means `r`, so `io.open(path)` is a read and reaches 723. The
character decides, not its position, so `w+` reads nothing and writes.

A mode the source does not state is a third case. For 723 it is treated as a
read, because that is what an absent mode means and the conservative reading of
an unknown mode is the one that can disclose. For 721 it is reported at
`confidence = "low"`: the path is firmware state either way, we cannot claim a
write we cannot see, and neither can we call the file safe.

## What 727 considers a ceiling

727 is the rule that was most expensive to get right, and the measurement is
worth recording. The first version asked a single question - is the loop limit a
literal constant - and it reported **65 findings on lua-doctor's own source**, every
one of them a false positive:

```
for _, finding in ipairs(report) do findings[#findings + 1] = finding end
for k in pairs(t) do keys[#keys + 1] = k end
for index = 2, #node do args[#args + 1] = node[index] end
```

Two idioms, and both are the most common lines in the language. A count nobody
wrote down is not a count nobody can see. So the question is not "is the limit a
literal" but "**can the source see a ceiling**", and it can in four ways:

| Loop | Bounded when |
| --- | --- |
| numeric `for` | the limit and the step are both constant-foldable, or the limit mentions a length (`#t`) |
| generic `for` | the iterator is a finite one: `pairs`, `ipairs`, `next`, a `gmatch`, a `lines()` call |
| `while`, `repeat` | the condition compares against a length, and a `repeat` does not end in `until false` |
| any of them | the body's own statements return or break before the loop can come back around, which is how `while true do ... return out end` is spelled |

A doubling is the exception that needs no unbounded loop at all: `s = s .. s`
costs 2^n whatever n is, and 32 turns of it is 4 GB, so it is reported inside a
bounded loop too.

### Strings and tables are not the same finding

A **string** accumulator is the shape that exhausts memory: the turn count
multiplies a size the script chose, so a counted loop with an unstated count is
the finding.

A **table** is bounded by the data that fills it. A script that collects N items
holds N items, which is the program working, not the program running out of
memory. A table is this finding only when even the turn count has no ceiling in
the source - a `while`, a `repeat`, or a generic `for` over an iterator the
source does not bound. That rules out the numeric `for` a programmer writes by
counting, which is where the last of the 65 came from:

```lua
for i = 1, select("#", ...) do
   output[#output + 1] = tostring((select(i, ...)))
end
```

### `string.rep`

`string.rep(unit, n)` allocates `unit * n` bytes, so a count the request chooses
is the finding. A count the script computes is not:

```lua
string.rep(unit, luci.http.formvalue("n"))   -- 727
string.rep("  ", indent + 1)                 -- a design, not an attack
string.rep("-", 40)                          -- a ceiling
```

`make selfscan` is the regression test for all of this. It analyzes `src/` and
fails on any finding, so a rule that cannot tell an accumulator from a table
build does not survive.

## The file API table

`FILE_OPEN_APIS` names the functions that take a path and a mode, and which
argument holds each. `io.open` and `nixio.fs.open` are always recognised;
`file.open` carries `profile = "espressif"`, so it is only recognised when that
profile is loaded. A program with no `file` library is not reported for having a
function of that name.

## Extending a set

Add a line to the table. A vendor who cannot patch the module can still declare
their own sources, sinks and sanitizers through `--rules`, but the path sets
themselves are module data by design: they are short, they are read often, and
they are the part a reviewer needs to see in one screen.

Two shapes to avoid when adding an entry:

- Do not add a `prefixes` entry that a longer path could satisfy by accident.
  `"/etc/rc.local"` is an `exact` entry, not a prefix, so
  `/etc/rc.local.d/x` does not match it.
- Do not reach for a Lua pattern. If an entry needs a shape the fields do not
  cover, add a field with a test that cannot backtrack.

## One statement, one finding

Two codes can come out of the dataflow pass that this module also produces: 721
under the espressif profile, and 722 under the openwrt and luci profiles. Where
that happens the module stands down rather than reporting the same statement
twice.

For 722 that has a consequence worth stating plainly. The dataflow pass reports
a config write whose value carries untrusted data as **709**, and its generic
dynamic-argument path reports a **722 with no destination**. The rule module
suppresses itself in both cases, which is correct and is why nothing is
duplicated, but it also means a 722 reaches the report without its `chain` field
on exactly those statements.

The fix belongs in `src/luadoctor/engine/taint.lua`, in `check_sink`, and is three
lines: skip `kind == "config"` sinks there, since this module owns 722 and is the
only layer that can name the config path the value lands in. With that in place
every 722 carries a `chain`, a tainted config write is a 722 rather than a 709
(which is the more accurate code: nothing executes at that statement), and
nothing is reported twice.

Until then:

- `--std +openwrt --no-dynamic-sinks` leaves the dataflow pass reporting only
  proven untrusted flow, so this module's 722, with its `chain`, is the only 722
  in the report. `test/spec/firmware_spec.lua` asserts exactly that.
- `uci.add` is declared with a fourth value argument that the three-argument call
  does not have, so the dataflow pass cannot see that write at all. This module
  takes the last argument as the value when the declared index is absent, which
  is what makes `uci.add` reportable today.

## Cost

Seven detectors, each one depth-first walk of the parsed program, plus one
memoized re-derivation of the dataflow pass's findings, and only when a
candidate statement exists at all. Measured over an 80x size range, the seven
walks cost 8.1 to 11.9 ms per 1000 lines with no upward trend, and 1,751 lines
to 140,001 lines - a factor of 80 - took 94 times as long, the excess being
collection on the 100,000-statement table of findings:

| lines | walks | ms per 1000 lines |
| --- | --- | --- |
| 1,751 | 0.0141 s | 8.1 |
| 3,501 | 0.0286 s | 8.2 |
| 7,001 | 0.0593 s | 8.5 |
| 17,501 | 0.1536 s | 8.8 |
| 70,001 | 0.8321 s | 11.9 |
| 140,001 | 1.3256 s | 9.5 |

The two walks that follow a local variable, `source_of` and `path_prefix`, are
the only ones that leave the statement they were called on. Both visit each local
at most once per call, both are capped at depth 16 (so an alias chain of 40 names
ends in silence rather than a guess), and `source_of` additionally caps itself at
2000 steps. A file written to be expensive therefore loses a `source` field, not
the run.

## CGILua profile

The `cgilua` profile declares global sources (`cgi` at certain confidence,
`RowId`, `DBTable`, `NextPage` at high), call sources (`web.cgiToLuaTable` at
certain, `web.cgiSearch`, `web.cgiFindButton`, `web.cgiFindToken` and
`SAPI.Request.servervariable` at high, `cgilua.cookies.get` at medium), and the
vendor wrappers `util.runShellCmd` and `util.shellCmdOutput` as exec sinks. Both strip
`; ` $ & | < >` from the command but not from their `options` argument and leave `(`, `)`
and newline, so the command argument carries `filters = {[1] = ";`$&|<>"}`: a flow into it is still
reported, one confidence step lower, with a message naming what the filter removes and what still
passes. A tainted `options` argument is reported at full confidence. A sink entry in a `--rules`
profile may carry the same `filters` field (a table of argument position to the characters the
callee strips; each position must also be in `arg`).

## Entry points

A profile may declare functions that are called with request data, for a web
server whose dispatch the analysis cannot follow (`--whole-program` follows a
route-table literal, but not a computed one or a handler registered later):

```lua
return {
   name = "myvendor",
   entry_points = {
      {pattern = "handle_*", arg = {1}, confidence = "medium"},
   },
}
```

`pattern` is matched against a function's full name (`M.on_request`) and then its
short name (`on_request`), with the same `*` and `?` wildcards as sources and sinks.
`arg` lists the parameter positions that start tainted (default `{1}`, or `"*"`
for every parameter and the vararg — see below). A sink
reached from such a parameter is a 709 with the entry point as its source, so the
708 "exposed sink nothing feeds" at that site is dropped. The cgilua std declares
`*Handler` with argument 1 for the mesh JSON-RPC handlers.

An entry may also carry `file`, a glob matched against the path of the file as it
was scanned (`*` crosses `/`). It then applies only to functions in matching
files, so a vendor whose handlers follow a per-folder convention can say "every
function in these files":

```lua
{pattern = "*", file = "*/meshlib/mesh*.lua", arg = {1}}
```

`arg` may also be `"*"`, which means every parameter the function has **and** its
vararg. Use it where the caller's arity is the request rather than the signature —
a dispatcher that calls `handler(node, <every URL segment>)` does not promise a
fixed number of arguments. It is the only way to reach a handler written
`function(...)`, which has no formal parameter at any position:

```lua
{pattern = "*", file = "*/controller/*.lua", arg = "*"}
```

A `file` glob is matched with `*` crossing `/`, so `*/controller/*.lua` means "the
path contains `/controller/` and ends in `.lua`", nested controllers included. The
path is normalised first (`.` and `..` segments are folded out textually), so
`controller/../other/x.lua` is judged by where it resolves, not by the text it contains.

That is what the luci std declares. Without it, `function(...)` and every
argument past the first were reachable to nobody: a `...` has no parameter
position to list and the positions past the node name were never declared.

A source string given to `check_source` has no path, so a `file` entry never
matches it. What a CGILua scan still does not follow is listed in one place in
[docs/usage.md](usage.md#what-a-cgilua-scan-does-not-follow).

### What an entry point is allowed to claim

An entry point asserts that the function *is* called with request data. It does
not assert that anything calls it, so it cannot be reported at `certain` the way
`luci.http.formvalue` is: `formvalue` reads the request, while an entry point
infers it from where the function sits. Every std that declares entry points
reports them at `medium` (`#178` for the cgilua mesh handlers, `#226` for the
LuCI dispatcher) and this is why.

## Stores

A profile may declare a store: calls that write a value somewhere a later call
reads it back from, such as a configuration database. A request value written
there and read back into a command is one flow, reported as `729`:

```lua
return {
   name = "myvendor",
   store_writes = {
      {pattern = "cfg.set", store = "cfg", table = 1, column = 2, value = 3},
      {pattern = "cfg.save_row", store = "cfg", table = 1, row = 2},
   },
   store_reads = {
      {pattern = "cfg.get", store = "cfg", table = 1, column = 2},
      {pattern = "cfg.get_row", store = "cfg", table = 1},
   },
}
```

Every field but `pattern` and `store` is an argument position. A write writes
either one `value` (into `column`) or a whole `row`, never both; a read has
neither. The table must be a literal (or fold to one) on both sides, or the call
is not paired. The column comes from a literal `column` argument; a row write or
a row read stands for every column of its table and pairs at low confidence. The
pairing runs over the whole scan after it ends, so the write and the read may
be in different files and `--whole-program` is not needed. The cgilua std
declares the `db.*` API this way.

## Validators

A profile may declare functions that validate their argument, used as a guard
before a sink (`if is_ipv4(x) then run(x) end`):

```lua
return {
   name = "myvendor",
   validators = {
      {pattern = "validations.is_ipv4_address"},
      {pattern = "validations.is_fqdn_address"},
   },
}
```

A guard does not transform the value, so the flow is still reported — a static
pass cannot be sure the check rejects every shell metacharacter — but one
confidence step lower, with the guard named and a `guarded_by` field in the
report. Treat it as "probably handled, confirm the validator"; `--min-confidence`
filters these out when you trust the checks, and the `fix` handoff passes the
guard name to the agent. The cgilua std declares the CGILua IP/host validators.
