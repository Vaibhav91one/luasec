# Measured precision

Numbers here are measurements against real firmware Lua, not against the test
fixtures. The corpora are cloned by `make corpus` and are gitignored.

## Which numbers here are authoritative

Three copies of this measurement exist and they are not equal in kind.
`scripts/precision-golden.lua` is the measurement: it is frozen, `make
precision` compares a fresh run of the analyzer against it, and it is the copy a
contributor updates when a rule changes what the tool finds. The per-code table
below is that file written out for a reader. Everything else in this document is
prose about how the number got here.

**The table is the only place in this document where a current per-code total
appears.** Prose names the change that moved the count - usually the PR that made
it - and leaves the figure to the table. A sentence saying "after #225" stays
true forever; one saying "is 33" is a time bomb that only a reader reading
closely can defuse, and two of them reached review before this rule existed
(#258). The warning this document used to open with was correct and had
demonstrably not prevented it, which is why it is a rule now.

`test/spec/precision_spec.lua` holds the prose to it: a sentence claiming a count
for the corpus as it stands now has to agree with the frozen measurement, and a
sentence about a run that has already happened - one naming the PR, or saying
`was` - is left alone, because a historical figure is correct as history and is
not drift. `test/spec/precision_golden_spec.lua` holds the table itself against
the same file, in both directions.

So a contributor who changes what the tool finds edits two files in one commit:
`scripts/precision-golden.lua` and the table below. Prose changes only when the
story changes.

## The corpora

| Corpus | Files collected | What it is |
| --- | --- | --- |
| `corpus/luci` | 73 | current LuCI libraries |
| `corpus/luci-1806` | 460 | LuCI at commit `20b3600d` on the `openwrt-18.06` branch: the `.lua` web layer, written as root-executing CGI |
| `corpus/openwrt-packages` | 0 | the OpenWrt package tree: smaller scripts, no `.lua`, scanned anyway |
| `corpus/luajit` | 29 | LuaJIT, the dialect firmware vendors use for speed |
| `corpus/lua-resty-core` | 36 | `openresty/lua-resty-core` v0.1.32 — the FFI layer the `ngx.*` API is built on |
| `corpus/luasocket` | 76 | `lunarmodules/luasocket` v3.1.0 — the socket/http/mime libraries OpenResty ships |
| `corpus/lua-resty-jwt` | 6 | `cdbattags/lua-resty-jwt` v0.3.2 — JWT signing and claim validation |
| `corpus/lua-cjson` | 6 | `openresty/lua-cjson` 2.1.0.19 — the JSON codec, over untrusted request bodies |
| `corpus/lua-nginx-module` | 4 | `openresty/lua-nginx-module` v0.10.31 — the `ngx.*` modules themselves |
| `corpus/lua-resty-lock` | 1 | `openresty/lua-resty-lock` v0.09 — shared-dict locking |
| **total** | **691** | |

`make corpus` clones ten repositories. Eight contribute the `.lua` files counted
above; `openwrt-packages` contributes none and is scanned only because it is the
smaller script tree worth watching. `luci-1806` is pinned to a commit and the six
OpenResty entries are pinned to a released tag's commit, because a measurement
against a moving branch is not a measurement: the commit is named so a reader can
tell whether they are looking at the same code.

`luci`, `openwrt-packages` and `luajit` are **not** pinned. They are `--depth 1`
clones of a default branch, so what `make corpus` fetches for them changes
whenever upstream moves and the file counts above have merely happened to hold.
That is a real gap in the measurement, it predates #262, and #262 did not widen
it. The per-entry `.lua` floors in `scripts/clone-corpus.sh` are all that stands
behind those three: they make an empty or truncated checkout loud, and nothing
more.

`scripts/clone-corpus.sh --verify` checks that every declared entry exists, holds
at least its declared floor of `.lua` files, and sits at its pinned revision, and
`make precision` runs it **before** the analyzer. Two of those catch things the
frozen file counts cannot: a pinned entry moved to another commit has the same
number of files and different code in them, and an entry that cloned into an empty
working tree yields a smaller number that reads exactly like a rule change. The
verify names the entry and prints both hex values instead of reporting arithmetic.
`test/spec/corpus_spec.lua` fails if that verify is ever removed from the path or
moved behind the analyzer.

691 is how many `.lua` files `make corpus` collects. 964 is how many paths
luasec selects from them and analyzes, the difference being the extensionless
CGI handlers and generated scripts a firmware image carries, plus the non-`.lua`
files the walk admits inside the OpenResty checkouts (see below). The headline
counts what was analyzed, because that is what produced the findings.

Command:

```sh
bin/luasec --std +openwrt+luci+luajit --format json -o /tmp/corpus.json corpus
```

## What #262 added, and what it did not

The corpus held no OpenResty at all before this: every source the `openresty` std
declares is a firmware API, so no openresty source was in scope and a change to
that profile could not move the number. #227, #240 and #263 each shipped such a
change with a corpus figure of 0 before and 0 after, which is the absence of a
measurement rather than a measurement.

So the headline below is much larger than it was, and the split is the whole
content of this section. Over the four entries that were already here, the run is
**identical to main's, finding for finding**: the multiset of
`(code, file, line, column, message)` taken over `luci`, `luci-1806`,
`openwrt-packages` and `luajit` is equal before and after, and every code reported
before is reported the same number of times. All of the increase is in the six new
directories, and no finding in the new directories matches any finding from the
old run, so nothing was counted twice across the two checkouts.

**What the new entries buy is FFI false-positive surface and crypto/encoding
surface, not request-handler flow.** They contribute nothing at all to 704, 708,
709, 710, 712 or 724, and the reason is the one #262 predicted before it was
written: these are libraries, and a library is not a request handler.
`lua-resty-core` *is* the layer the `openresty` sinks are built on, so it contains
no call to any of them. `lua-resty-jwt` is crypto and encoding, where a false
positive costs most, and it is the entry that most earned its place.

**What the next person to extend this corpus should add is a deployed nginx
configuration, not another library.** Nothing in this queue yet measures an
actual request handler reaching an OpenResty sink, and that is still the gap: a
`server {}` / `location {}` block whose `content_by_lua_block` reads
`ngx.var`, `ngx.req.get_uri_args()` or `ngx.req.get_headers()` and reaches
`ngx.exec`. That shape is configuration rather than a library, so it does not
exist upstream to be cloned.

### Is OpenResty Lua representative?

Partly, and the parts are worth naming rather than averaging. What is here is
**upstream release trees, not deployed configuration**: each entry is a tagged
release of a public repository, checked out at that tag's commit, carrying no
site-specific `nginx.conf` and no request handler of its own. Within that, the
idiomatic coverage is real — socket and HTTP client code, a JSON codec over
untrusted bodies, JWT signing and claim validation, and an FFI layer written by
people who are not writing a firmware CGI script, which is exactly what this tool
most needed to be checked against.

Two caveats a reader should not have to discover by reading the table:

1. **Most of the Test::Nginx `.t` files in the new checkouts are Perl, and the
   walk reads them as Lua.** `lua-resty-core` and `lua-nginx-module` ship their
   test suites as `.t` specs written in Perl with Lua inside heredocs, and the walk
   has no `.t` in its not-Lua list. **Every parse failure, unsupported dialect and
   dialect mismatch the new entries contribute is on a file that is not Lua — all
   of them, and none on a `.lua` file.** That is a walker defect rather than a
   property of OpenResty; it is filed as **#288** and it is the first thing to fix
   before reading anything else in the OpenResty rows, because it accounts for
   roughly half of what those entries contribute to this table.
2. **`lua-nginx-module` is a C project.** Its four `.lua` files are Test::Nginx
   helper libraries under `t/lib/`, not the `ngx` API, which is C. It is in the
   corpus because its `.t` specs exercise `ngx.exec` and the subrequest sinks
   #227 added — not because it ships Lua that runs in production.

The `.git/packed-refs` of two checkouts is read as Lua too, because whether
`looks_like_lua` accepts one depends on whether the word `lua` appears in its first
512 bytes, which depends on which branches upstream had at clone time. An earlier
draft of this change removed those findings by relocating the git directories
outside the corpus, and that was reverted on purpose: it hides the evidence, fixes
nothing, and a corpus quietly shaped to stop tripping a defect makes that defect
harder to find next time.

## Result

1136 findings over 964 files, 403 of them carrying at least one (42%), after nine
rounds of fixing false positives
that this corpus found, after the release review found more, and after 747 was
narrowed to the cases where a name and a value both say a credential is
embedded.

**#262** moved this number, and not one finding of the increase is in code that
was already here. Six OpenResty repositories joined the corpus, pinned to
released tags; the four firmware entries were re-measured alongside them and came
out identical to main's, finding for finding and code for code. The split, the
representativeness question and what the new entries do and do not buy are in
"What #262 added, and what it did not" above. **What they buy is FFI and
crypto/encoding false-positive surface, not request-handler flow** — they
contribute nothing to 704, 708, 709, 710, 712 or 724, because a library is not a
request handler. A large share of the new findings are in files that are not Lua
at all, which is #288 rather than anything about OpenResty, and it is named here
because the table below cannot be read correctly without it.

**#268** moved this number by one, in the one direction a security tool is allowed
to. The OpenWrt profile declared one of the three functions nixio's process
module exports. `process.c:325-335` dispatches `exec`, `execp` and `exece` to one
`nixio__exec`, which reads the command from position 1 for all three, so the two
undeclared ones are now declared: `nixio.execp` and `nixio.exece`, both `arg =
{1}`. One new 709, in a stock LuCI controller:
`luci-app-nlbwmon/luasrc/controller/nlbw.lua:46`. It is a true positive and a
real one - `action_restore` unpacks an uploaded backup with
`exec("/bin/tar", { "-C", dir, "-vxzf", tmp, unpack(files) })` at line 207, where
`files` is the list of archive entry names read back out of that archive by
`io.popen("/bin/tar -tzf %s" % tmp)` at line 179, so attacker-supplied bytes
reach `argv` of `tar -x`. Line 46 is the `nixio.exece` that runs it. Nothing was
removed and no other code moved, so under the corpus of that day the headline was
up by one and 709 was up by one; both figures are unchanged today.

The same change removed two declarations that could never match anything:
`nixio.process.execute` (nixio exports no `execute` - `process.c:440-442`
registers `exec`, `execp` and `exece`) and `nixio.process.exec`. The second is
the subtler one and the issue did not name it: `nixio.process` is not a namespace
at all. `process.c:448` is `void nixio_open_process(lua_State *L) { luaL_register(L,
NULL, R); }` - no `lua_newtable()`, no `lua_setfield(L, -2, "process")` - so the
table is the one already on the stack, which is `nixio` itself. Ten of nixio's
seventeen openers are written that way and three are not; `fs.c:550` does push a
table and name it `fs`, and that one really is `nixio.fs`. Nothing in the corpus
calls `nixio.process.*` and nothing can.

What that costs is a spec, not accuracy: `test/spec/registry_export_spec.lua`
reads the `luaL_register` tables out of every `.c` in `corpus/` and every
module out of every `.lua`, and fails on any registry declaration that names
something none of them export. It catches the two declarations removed here, and
only those: `nixio.execp` and `nixio.exece` had no declaration to check, so the
100/100 they scored was invisible to it and to everything else. What it stops is
the next dead declaration, not the next missing one.

**#265** moved this number, and in the one direction a security tool is allowed
to. The OpenWrt profile declared `nixio.exec` as taking its command first, which
covers `nixio.exec(command)` and is wrong for
`nixio.exec("/bin/sh", "-c", command)` - the form OpenWrt code actually writes,
where the command is third. The declaration now carries both positions, so both
report. Five new 709s, all of them the shell form in real firmware:
`admin/system.lua:416` and `:446`, `mini/system.lua:233`, and
`failsafe/failsafe.lua:170` and `:200`. Each is a value reaching a shell from
`fork_exec`/`ltn12_popen`, which the dispatcher calls with request data. Those
five lines previously scored `100/100 (good)`. Nothing was removed and no other
code moved: the headline is up by five and 709 is up by five, and the number of
files carrying a finding is unchanged because every one of them already carried
one.

What it costs: `nixio.exec` passes arguments 2..N straight to `execv()` as
`argv[]` and involves no shell (`libs/luci-lib-nixio/src/process.c:32`), so in a
*direct* call the third argument is an option, not a command, and we now report
it. No corpus file does that. Telling the two forms apart needs a per-position
guard the sink declaration does not have - position 3 counting only when
position 2 is the literal `"-c"` - which is engine work rather than a data
change.

**#238** did not move this number, and that is the point of it. 724 was the
second-largest family here at 25, all 25 at `high`, and 17 of them were the same
non-finding: a LuCI CBI hook whose command is a compile-time literal, which is
how a config file says "restart this service". Those 17 now report at `medium`
and low confidence with a note saying the command is a literal. Nothing is
hidden - the finding is still made, because the exposure is real - but
`--severity-threshold high` no longer reports them. The count is the same before
and after and every other code is byte-identical; what moved is the severity mix,
from 190 `high` findings to 173. The 8 that stay `high` are handlers whose
command is built from something `const_eval` cannot fold, and they keep the
registered severity.

Two changes moved this number since the last release, and neither is a
regression.

**#226** modelled the LuCI dispatcher's arguments, so twelve sinks that used to
report "here is a dangerous call, nothing feeds it" now report the flow that
feeds them, and the weaker shape-only and exposed-sink findings those twelve
replaced are no longer reported beside them. Fifteen findings left, fourteen
arrived, and the fourteen are the stronger kind.

**#225** stopped 708 from *replacing* the 701 at the sink it names. An exported
function whose execution sink is fed by something the file cannot fold was
getting one finding, the 708, and nothing at all for the sink itself. 708 still
reports "nothing in this file feeds it"; the 701 reports what is built into the
command, and both are true of the same line. Thirty-three findings arrived, 29
at 701 and 4 at 704, every one of them a sink already being reported as an
exposure. 708 is unmoved by that fix, because what changed is that it no longer
*replaces* the sink report rather than that it reports less. Three of the sites
#225 restores were also among the nine #226 turned into a 709, which is why
this reads 29 where #225 measured 32 against the previous main. No file that
was clean became dirty.

This number has been wrong three times, each time because the headline was
edited by hand and the per-code table was not, and twice more in prose, where a
sentence carried a figure with nothing to compare it against (#258).
`test/spec/precision_spec.lua` parses this file and fails the build if the
headline and the table disagree, and if a sentence claims a count for the corpus
as it stands now that `scripts/precision-golden.lua` contradicts. The command
above is here so the number can be reproduced rather than believed.



Hand-audited sample by code:

| Code | Count | Assessment |
| --- | --- | --- |
| 724 RPC handler | 25 | true, at two strengths. The rule that matters most after 709, and the one the release review found crashing on every controller with a non-hook field. Down 3 from 28 with #226: the three controller methods that now carry a real flow to their sink (`startstop`, `lxc_create`, `iface_reconnect`) report a 709 instead of the weaker "exposed, nothing feeds it". Unmoved in count by #238 and down 17 in severity: 17 of the 25 are a CBI hook running a literal command, which is this corpus's spelling of "restart this service", and they now report at `medium`/low confidence instead of `high`. The 8 that stay `high` all reach a sink whose command is built from something that does not fold - `ddns`'s `CTRL.luci_helper` is the clearest - and they keep the registered severity |
| 708 exposed sink | 22 | mostly true: an exported function in a LuCI library calls an execution sink and nothing in that file feeds it. Fixed after review: it was also firing on functions the file itself called, and its registry message, doc row and registered severity disagreed. Down 3 from 36 with #226, for the same reason 724 fell: three exported functions now carry a named flow to their sink. Unmoved again in #225 - the fix there stopped it *replacing* the 701 at the sink it names, so the same sinks are reported and most of them now carry their 701 as well. Down 2 with #281, from `ccache.lua`'s `_load_sane`, which is a `local function` whose only call - `local modcons = _load_sane(encoded)` - was invisible to `callgraph.call_sites` because it is an assignment and not a whole statement, so the file read as one that never fed it. #281 also *tightened* this rule rather than only widening it: a resolved call now withholds 708 only when it passes an argument the file cannot fold to a constant, because for an exported handler - whose real callers are in another file, since LuCI registers it by name - an in-file call proves nothing about the path an attacker would take. Under the looser rule `luci-splash`'s `call(cmd)`, which `os.execute`s its argument and is called twice with string literals, lost its 708 and gained no 709, which is silence on a reachable sink; the tightened rule keeps it |
| 747 hardcoded secret | 15 | was 17 and every one of the 17 was a false positive; see below. It then went to 0 and came back as 2, because widening it to the forms firmware actually uses — a `uci.set` key argument, a CBI `.default`/`.value` field, a value concatenated at author time — also made it read `public_key.datatype = "and(base64,rangelength(44,44))"`, a CBI validator expression on a field that happens to be named after a credential. Those 2 are gone: only the fields that carry a value count, and only the profile-declared writers and real UCI cursors count as config writes. The rule's true positives are all fixtures, because the four firmware entries contain no hardcoded credential. **#262 moved this off zero, and every one of the 15 is a false positive** — see below. |
| 901 parse failure | 268 | true for the ten that were here before #262: real Lua the parser still rejects. Four of the original 14 (gettext escapes such as `"\$"`, which Lua 5.1 accepts) now parse through the escape retry (#181) and are analysed. All 258 that #262 added are the opposite case — **files that are not Lua at all**, which the walk selected and the parser then could not read Up hard with #262, which added the six OpenResty checkouts: **all 258 of the new ones are on files that are not Lua** (250 Test::Nginx `.t` specs written in Perl, 2 `.git/packed-refs`, a `.stp` probe, a Makefile and two shell scripts). None is on a `.lua` file. See #288 below. |
| 727 unbounded growth | 16 | true after narrowing: string accumulation in a loop with no visible ceiling. Up 2 with #262, both in `luasocket`. |
| 707 FFI escape | 401 | true: LuaJIT source, and with #262 the first non-LuaJIT FFI in the corpus Up hard with #262, which added `lua-resty-core` — **that entry is the FFI layer the `ngx.*` API is built on, so it is FFI by construction**, and 337 of the increase are its `.lua` files. The OpenResty entries are the first thing this corpus has contained that this rule could be checked against at all; before them this row was LuaJIT only. |
| 903 dialect mismatch | 192 | true but mislabelled. The ten that predate #262 are all the 5.3 bitwise operators under `--std luajit`, and the message calls an operator an API; that part of the row is unmoved and still wrong. #262 added the other 172, 171 of them Test::Nginx `.t` specs the walk read as Lua (#288) and the rest from `lua-nginx-module`'s `util/gen-lexer-c`, a C program Up hard with #262 for the same reason as 901: 171 of the increase are Test::Nginx `.t` specs. The ten that predate it are unchanged. |
| 741 obfuscated loader | 0 | was 5, and all 5 were false. Down 2 with #235: `luci-base`'s `cbi.lua` defines `load` as its own module loader over `loadfile`, so `load(node, name)` at line 581 is module loading, not a hidden payload. Down 2 more with #256: `defined_function` resolved local bindings only, so a **global function statement the file defines** had no binding to follow and the walk could not read it. `luadoc`'s `lp.lua:104` is `loadstring(translate(s))` where `translate` is defined 61 lines earlier as a global `function translate(s)` and only rewrites template markup — one site, counted twice because the corpus holds two checkouts of openluci/luci (`corpus/luci` and `corpus/luci-1806`) and `lp.lua` is byte-identical between them (`cmp` clean). The same double-counting is why #235's drop was 2 and not 1: the CBI file appears in both checkouts, as `luci-base` in one and `luci-compat` in the other. **The 1 that remains is a different defect and is still wrong.** `genlibbc.lua:145` is the LuaJIT build tool handing the output of `transform_lua` to the standard `load`. It is not the #256 class: `transform_lua` is a `local function` (`genlibbc.lua:48`), which `defined_function` already resolved — the finding comes from `shape_of` reading `string.gsub(code, "PAIRS%((.-)%)", function(var) ... end)` inside it as a substitution decode, and that shape is a real decoder shape rather than a gap. So the column was 5 findings over 3 sites before #235, 3 over 2 after it, and 1 over 1 after #256 |
| 709 injection | 23 | true, and the one that matters. Up from 5 with #226, which modelled the arguments `luci.dispatcher` calls a controller method with — the LuCI handlers this corpus is full of were previously reported as "exposed, nothing feeds it". Nine of the twelve are sites that carried a shape-only 701/702 instead (`adblock:75`, `cshark:56`, `diag:36`, `mwan3:102`, `network:302`, `network:412`, `status:65`, `status:85`, `system:183`); three are flows nothing reported at all before (`ddns:310`, `lxc:70`, `network:272`). All twelve name their source, and all twelve are `medium`: an entry point makes an argument reachable, it does not prove the dispatcher that reaches it is itself reachable. Up 5 more with #265, which declared the shell form of `nixio.exec` (`admin/system.lua:416` and `:446`, `mini/system.lua:233`, `failsafe/failsafe.lua:170` and `:200`) — five call sites, five findings, none of which was previously reported by any code. Up 1 more with #268, which declared the other two functions nixio's process module exports (`nixio.execp` and `nixio.exece`): `luci-app-nlbwmon/luasrc/controller/nlbw.lua:46`, where the archive entry names read out of an uploaded backup by `io.popen("/bin/tar -tzf %s" % tmp)` at `:179` reach `execve("/bin/tar", {..., unpack(files)})` at `:207`. The pre-existing five are unchanged, including the two from #58 (`cshark.lua:73`, `wol.lua:85`) |
| 701 shape-only | 67 | true: a sink whose argument the analyzer could not trace, including sinks whose result is used (assigned to a local, passed to another call, or wrapped in an expression) that were previously invisible because only bare statement-level calls were checked. Down 3 to 22 with #226, then up to 51 with #225: that is where this row stops being an undercount. An exported sink used to be reported as a 708 *instead of* its 701, and 29 of these are the ones that suppression was eating. Each one is the same shape-only finding the tool already reports in the same file when the sink is not exported, and no file that was clean became dirty. Up 18 with #262, 17 of them in Test::Nginx `.t` files read as Lua and one in `luasocket`'s `src/ftp.lua`. |
| 703 file write | 25 | true: writes outside /tmp and /var/run, including sinks nested in expressions. Up 8 with #262, all in the new OpenResty entries. |
| 702 env manipulation | 19 | true: setfenv grants and _G metatables, including sinks whose result is used in an expression. Down 6 from 21 with #226: those six sites now report a 709 naming the source. Up 5 with #262, all in Test::Nginx `.t` files. |
| 704 dynamic load | 21 | true: `dofile`/`loadfile`/`load` of a path the file cannot fold to a constant, including calls whose result is used. Up 4 from 17 with #225, for the same reason as 701: four dynamic loads inside exported functions were being masked by the 708 at the same sink. (The neighbouring 703 and 702 rows carry labels from an older catalogue; the counts are the measured ones and those two labels are a separate fix.) |
| 705 dynamic require | 23 | true after the rule was un-inverted; see below. Now also catches dynamic require in a local assignment. Up 4 with #262, all in the new OpenResty entries. |
| 710 dynamic code | 1 | true by the rule, low real risk: `luajit/dynasm/dynasm.lua:626` compiles a file it read (`loadstring(s)` of `io.open(...):read`); a file read is untrusted by rule, and this is a build-time tool |
| 712 partial quote | 3 | true: a shell-quoted argument alongside an unquoted one, where the partially-quoted call is used in an expression. Up 2 from 1 with #226: at `diag:36` and `network:412` the tool can now see both halves of the command, so it reports which part was quoted |
| 725 env escape | 2 | true after 725 was narrowed from every setfenv to the dangerous ones. Up 1 with #262: `lua-resty-jwt`'s `lib/resty/jwt-validators.lua`, which replaces an environment for a claim-validation closure |
| 728 search pattern | 1 | a single finding, and it is the only one in the whole corpus: `lua-resty-jwt`'s `lib/resty/jwt-validators.lua:93`, `string.match(val, pattern)` inside `string_match_function`. That function is reached from `opt_check(pattern, ...)` and `opt_any_of(patterns, ...)` — the `pattern` is supplied by the *application's own* `jwt:verify()` options, and `val` is the claim out of the token. Reported as untrusted data used as a search pattern, the untrusted argument is the one being matched, not the one being matched against. The class is real — `string.match` does treat its second argument as a pattern — but this instance is the rule binding to the wrong parameter, and it is in the one entry added for exactly this shape |
| 711 backtick shell | 6 | new to this table, and **all 6 are false**. Every one is a Perl backtick in a Test::Nginx `.t` file that the walk read as Lua: `lua-nginx-module/t/060-lua-memcached.t:13` and `:061-lua-redis.t:15` are `my $pwd = \`pwd\`;`, and `lua-resty-core`'s three are the same idiom in `t/process-type-privileged-agent.t`. They are #288 again — the walk has no `.t` in its not-Lua list — and they are the reason 902 is non-zero. Recorded here rather than filtered, because a rule that fires on Perl syntax is a fact about the tool and the corpus that exposed it |
| 902 unsupported dialect | 6 | new to this table and non-zero only because of #288: all 6 are Test::Nginx `.t` files in `lua-nginx-module` and `lua-resty-core` that parse as Lua far enough to run but use a construct the configured standard does not have. Like 901 and most of 903, this is the walk reading a Perl harness, not a dialect gap in Lua anyone writes |

## What the corpus fixed

Four defects that no fixture had caught, each of which was a large share of the
findings:

1. **The file walker treated a firmware tree as if it were all Lua.** `.patch`,
   `.pem`, `.js`, `.po`, `.awk`, `Makefile` and `.luadoc` were all scanned, because
   they begin with dashes and a Lua comment does too. 1404 files collected instead
   of 562, and 674 findings were all noise. Now an extension decides it when we
   know it, a name list rejects build files, and a content marker rejects diff and
   PEM headers.
2. **705 fired on constant `require`.** The rule was inverted: it reported a
   module name that *was* computable, which is every file in existence. 112 false
   positives on the corpus.
3. **727 reported collector tables.** `for k, v in pairs(...) do out[#out + 1] = v
   end` is an idiom, not a memory-exhaustion risk. 147 findings, essentially all
   of them that. The rule is now about string accumulation only.
4. **725 reported every `setfenv`.** In LuCI that is how a form object is
   instantiated: `setfenv(form, getfenv(1))(m, wdg)`. The rule now reports a
   replaced *caller* environment, an environment that grants a dangerous library,
   or a metatable on `_G`.

The release review added five more, all of them in the same class: a defect that
made the tool *silently* wrong rather than loud. A severity threshold could hide
901 and 904, so an operator running `--severity-threshold high` got a green build
for every file that failed to parse. A multi-assignment read the first
right-hand side for every target, which both invented an injection and hid one. A
multi-line file with tens of thousands of one-line functions took 19 minutes in a
pass that scanned every line once per function. A directory name an attacker chose
was interpolated into our own shell. And 708 reported functions the file itself
called.

Two more came from reading the findings rather than the rules:

5. **Constant folding silently failed on numbers.** The parser keeps a number's
   source text, so `1` folded to the string `"1"`. Arithmetic never folded, and a
   number compared equal to its own text.
6. **The rule context resolved only literal callee paths.** `local sys =
   require("luci.sys")` then `sys.exec(...)` was invisible to every rule module,
   so a real LuCI handler produced nothing. It now shares the engine's
   alias-aware resolver, and prunes function bodies from their definitions so
   each call is visited once.

7. **`--severity-threshold` turned "I could not analyze this" into "clean".** 901
   and 904 describe the analyzer, not the code, so no threshold may drop them. A
   file that could not be analyzed now fails the run and says so on stderr.
8. **A path reached our own shell.** Lua's `%q` escapes only `"` and `\`, so a
   directory named `/tmp/$(cmd)` ran a command substitution inside luasec. The
   path now travels through a file, and `find -print0` keeps a newline in a
   filename from becoming two paths.
9. **A multi-assignment read the wrong right-hand side.** `a, b = tainted, "safe"`
   reported both as injected, and in the other order hid the injection.
10. **The 708 pass was quadratic** in functions x lines. 32,000 one-line functions
    took 19 minutes. Lines are indexed once, and above a few thousand lines the
    cross-function passes are skipped with 904 rather than run for minutes.
11. **708 reported functions the file itself calls**, and nothing in the file is
    untrusted.
12. **A "quoting helper" was any function whose body contained an apostrophe**, so
    `log_it(s)` writing "user's input" counted as quoting.
13. **The sanitizer fact never reached a report.** A correctly quoted command was
    indistinguishable from an unquoted one at identical severity and exit code.
14. **708 replaced the 701 at the sink it named.** The exposure pass marked the
    sink's location "already reported" in the same table the shape-only pass
    reads, so the 708 and the 701 could not both stand. The command was built
    from a value the file cannot fold, and the report said only that nothing in
    this file fed it. `luci-app-lxc/controller/lxc.lua:70` - six
    dispatcher-supplied arguments interpolated into a shell command with no
    quoting - came back with one low-confidence note about exposure and nothing
    about the sink. #225, 33 findings over this corpus.

## Reproducing this

```sh
make corpus
bin/luasec --std +openwrt+luci+luajit --format json -o /tmp/corpus.json corpus
jq -r '[.findings[].code] | group_by(.) | map({c: .[0], n: length})' /tmp/corpus.json
```

## What is still noisy

### 747, and what it took to measure it honestly

747 was the weakest rule in the catalogue: on this corpus every one of its 17
findings was a false positive, in two shapes. One was
`key = "-----BEGIN RSA PRIVATE KEY-----"` in
`luci-lib-px5g`'s `der2pem`, a table of the header lines a script wraps a key it
builds at run time - the marker, not the key. The other was
`cacert2:depends({auth = "EAP-TLS"})`, 16 times in luci's wireless CBI model: a
name that says secret and a value that is a protocol name.

Three changes, each with a fixture:

1. **A PEM header is not a key.** A value whose lines are all `-----BEGIN ...-----`
   or `-----END ...-----` lines is a marker and is never reported. A value that
   opens a block and carries a base64 body is the key, and is reported whatever
   it is called, with the body redacted by the header. A file holding a marker
   and a body as separate literals reports the body.
2. **The name list is two tiers.** A qualifying name (`password`, `api_key`,
   `psk`, `token`, `secret`, `privkey`, ...) carries the finding on its own and
   is reported at `high` confidence. A bare `key` or `auth` does not: the value
   has to look like a secret, and the finding is `low`. The case of the name is
   no longer part of the name, which also fixed a false negative - `API_TOKEN`
   and `PASSWORD` were invisible before, because the splitter only matched
   lower-case letters and a name spelled in capitals has none.
3. **The value has to look like a secret.** Length floors of 4 under a
   qualifying name and 12 under a bare one, plus rejection of paths, URLs,
   format strings, numbers, all-caps enums, placeholders, and values whose every
   part is protocol vocabulary.

Measured after the change, same command as everywhere else in this file. Against
the four firmware entries, as the table's frozen figure records:

```sh
bin/luasec --std +openwrt+luci+luajit --format json -o /tmp/secrets-after.json corpus
jq -r '[.findings[] | select(.file | startswith("corpus/lua"))] | length' /tmp/secrets-after.json
# 15, none of them in corpus/luci, corpus/luci-1806, corpus/openwrt-packages or corpus/luajit
```

Over the whole corpus the rule now reports 15, and **all 15 are false positives**.
That is a different failure from the one this section used to describe, and it is
a better one to have: a rule that finds nothing is untestable against real code,
while a rule that is wrong in a way this corpus can name is fixable.

All 15 are in `luasocket`, and they are two shapes:

- **`luasocket/src/ftp.lua:30`** is `_M.PASSWORD = "anonymous@anonymous.org"`, the
  RFC 2577 anonymous-FTP default, with the file's own comment saying it "should be
  changed to your e-mail". It is a protocol constant, not a credential, and the
  rule reports it because a qualifying name and a value that looks like one are
  both present — which is precisely what the rule says it does.
- **The other 14 are upstream test fixtures.** `luasocket/test/urltest.lua`
  contributes nine, and they are `url.parse` expected-value tables asserting how a
  `?` and a `#` inside a password are parsed:
  `password = "pass?#wd"`. `test/httptest.lua` and `test/ftptest.lua` each
  contribute one `password = "password"`, which is a placeholder the value
  heuristics do not currently reject.

So the rule has **no true positive anywhere in this corpus and no false negative
exposed by it**, and the fixtures are still what proves it works: a router script
shipping `ADMIN_PASSWORD = "admin"`, a WiFi generator shipping a PSK, an
`API_TOKEN`, a complete private key block, and a PEM body beside its header. Four
of the five are found at `high` confidence; the bare `key` beside a six-digit hex
value is found at `low`.

What the new corpus asks of 747 is concrete, and #262 does not fix it because
this issue owns no rule: **a value that is a placeholder, or that is RFC-mandated
rather than chosen, should not be reported at `high`.** `"password"`, `"pass?#wd"`
and the anonymous FTP default are all reportable-but-not-leaked. Tightening the
value heuristics is the change, and it should be taken against this measurement
rather than against fixtures alone.

What 747 gives up, stated rather than hidden: a bare `key` or `auth` holding
something under twelve characters, or a single lower-case word with no digit in
it, is not reported. `key = "timeout_ms"` and `auth = "EAP-TLS"` are silence
rather than a finding, and that is the trade - a bare name plus a bare word is a
table index about as often as it is a credential, and it was 100% wrong in this
corpus. Naming the value in a qualifying name gets the report either way.

### Still noisy, and not in this branch

- **903 is true but mislabelled.** The ten findings that predate #262 are all the
  5.3 bitwise operators under `--std luajit`, and the message calls an operator an
  API. The findings are honest about the file; the sentence about it is not. The
  rest of this row is #288 — Test::Nginx `.t` specs read as Lua.
- **901 is a dialect gap in the ten that predate #262, and a walk bug in the 258
  that came with it.** Ten files of real Lua still fail to parse. Four more used
  gettext escapes (`"\$"`, `"\+"`) that Lua 5.1 accepts and the parser rejected;
  since #181 they are parsed again with the escape rewritten to one of the same
  length and analysed. The rest are reported rather than guessed at, which is the
  right behaviour. The other 258 are Perl `.t` specs, two `.git/packed-refs`, a
  Makefile and two shell scripts that the walk selected because it has no `.t` in
  its not-Lua list and does descend into `.git/`; the parser is right to refuse
  them and the walk is wrong to have offered them. **#288.**
- **708's assessment says "mostly true" and has not been re-audited since the
  review fix.** The count is in the table above; what has not been re-checked is
  the claim beside it.
- **Nothing in this corpus measures an openresty request handler.** That is the
  gap #262 was opened to close and it is only partly closed: the profile now has
  measurement surface, and the surface is libraries rather than handlers. A
  deployed `nginx.conf` with a `content_by_lua_block` is what is missing, and
  nothing upstream ships one to clone.
