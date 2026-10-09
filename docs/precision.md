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

691 is how many `.lua` files `make corpus` collects. 707 is how many paths
luasec selects from them and analyzes, the difference being the extensionless
CGI handlers and generated scripts a firmware image carries, plus the non-`.lua`
files the walk admits inside the OpenResty checkouts. That was 964 until #288
and is 706 without the authored nginx.conf (#296, 707 with it), and the 258 paths the walk gave up were **250 Test::Nginx `.t`
specs, 2 `.git/packed-refs`, and six pieces of tooling** — a SystemTap `.stp`
probe, a C lexer generator, a `makefile.dist` and three shell scripts. **Not one
of them was a `.lua` file:** the walk selected 687 `.lua` files before #288 and
selects the same 687 after it. The headline counts what was analyzed, because
that is what produced the findings.

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
configuration, not another library. (An authored one now exists, and says what it does not stand in
for: see "An authored nginx.conf" below.)** Nothing in this queue yet measures an
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

Two caveats a reader should not have to discover by reading the table. Both
were written before #288 and both are shorter now, because the defect they
describe is fixed rather than moved:

1. ~~**Most of the Test::Nginx `.t` files in the new checkouts are Perl, and the
   walk reads them as Lua.**~~ **Fixed by #288.** `lua-resty-core` and
   `lua-nginx-module` ship their test suites as `.t` specs written in Perl, the
   walk had no `.t` in its not-Lua list, and it sniffed the first 512 bytes of a
   file for an opener — so it found `lua` in `use Test::Nginx::Socket::Lua` and
   read 250 Perl programs as Lua. Every parse failure, unsupported dialect and
   dialect mismatch those two entries contributed was on a file that is not Lua.
   `.t` is now in the not-Lua list and the content no longer gets to overrule a
   suffix. **What this cost is stated in full below**: 436 of the 466 parse and
   dialect failures went away, and so did 89 findings in six other codes that
   were real detections inside the Lua those specs carry in heredocs. That is a
   coverage loss, it is named there file by file, and it is filed as its own
   issue rather than absorbed into this number.
2. **`lua-nginx-module` is a C project, and after #288 it contributes nothing at
   all to this table.** Its four `.lua` files are Test::Nginx helper libraries
   under `t/lib/`, not the `ngx` API, which is C. They carried 0 findings before
   this change and carry 0 now, so the entry's entire measured surface used to be
   its `.t` specs — 377 findings, every one of them either a parse failure on
   Perl or a lexical-scan detection inside a heredoc. **That leaves
   `lua-nginx-module` with nothing to contribute to a false-positive measurement,
   and the honest reading is that the entry should be reconsidered or replaced by
   a deployed `nginx.conf`** — which is the same gap #262 named for the whole
   OpenResty queue and which nothing upstream ships to clone.

The `.git/packed-refs` caveat that used to stand here is **closed by #288**. It
was the same defect wearing a worse hat: the walk never descended into `.git/`, so
whether it read a packed-refs index at all depended on whether the word `lua`
appeared in its first 512 bytes — true for `lua-nginx-module` and
`lua-resty-core`, false for the other eight, and a function of which branches
upstream happened to have when `make corpus` cloned. It now never descends into
`.git/`, which is a category rather than a case: `packed-refs` can be renamed, a
packfile can have any name, and every checkout has one. An earlier draft of #262
removed those two findings by relocating the git directories outside the corpus,
and that was reverted on purpose — it hides the evidence, fixes nothing, and a
corpus quietly shaped to stop tripping a defect makes that defect harder to find
next time.

### An authored nginx.conf (#296), and what it stands in for

`test/fixtures/openresty-authored/nginx.conf` is **written by the maintainers**, not taken from a
deployment: fifteen `location` blocks whose `content_by_lua_block` bodies are typical request
handlers, each with the author's intent on its first line (`-- expect: 730`, or `-- expect: none`
for a handler that is safe). It is **part of the pinned corpus**: `scripts/clone-corpus.sh` copies
it to `corpus/openresty-authored/` and `--verify` diffs it against the fixture, so an edit that is
not followed by a re-measure fails there and names the entry. luasec itself now reads Lua out of an
nginx.conf: the bodies of every `*_by_lua_block { ... }` (`content_by_lua_block`,
`access_by_lua_block`, ...) are scanned with the `openresty` profile added to whatever `--std` says,
and a finding lands on the `nginx.conf` line and column (`src/luasec/cli/nginxconf.lua`). Not read:
the old string form `content_by_lua '...'`, and `*_by_lua_file` (the file it names is ordinary Lua
and is scanned as itself). `test/spec/openresty_authored_spec.lua` compares what luasec reports for
each handler with that intent.

**What the corpus run did:** 610 -> 620 findings and 706 -> 707 scanned files, and the whole
difference is this one file: 701 +1, 709 +5, 728 +1, 730 +3, ten findings in `nginx.conf`, each named
in the table below. Every other code, and the other ten entries, are finding for finding what they
were. The golden and this document move together in the same commit.

**What it stands in for:** the deployed `server {}` / `location {}` request handler that no upstream
repository ships and that this queue has none of. **What it does not stand in for:** real-world
recall or precision. The author wrote both the handlers and the intent, so it shows whether a known
idiom is handled, never how often real deployments differ from the author's imagination. Counting
its 10 findings as true positives would inflate this table: 8 are the intended finding and 2 are
known false positives (`/ping-checked`, `/kill`, below); a ninth handler, `/proxy`, is a miss.

Authored OpenResty handlers: 8 reported as intended, 4 silent as intended, 1 missed, 2 reported although safe (15 handlers).

| handler | intent | luasec reports | verdict |
|---|---|---|---|
| `/go` (`ngx.redirect` of a query parameter) | 730 | 730 certain | as intended |
| `/forward-host` (`ngx.req.set_header` from a request header) | 730 | 730 certain | as intended |
| `/cache-key` (`ngx.header[...] = ngx.var.uri`) | 730 | 730 medium | as intended |
| `/handoff` (`ngx.exec` of a query parameter) | 709 | 709 medium | as intended |
| `/ping` (`os.execute` with `ngx.var.arg_host`) | 709 | 709 medium | as intended |
| `/dns` (`io.popen` with a query parameter) | 709 | 709 certain | as intended |
| `/run` (`os.execute` of a JSON body field) | 709 | 709 high | as intended |
| `/find` (a query parameter as the `ngx.re.find` pattern) | 728 | 728 high | as intended |
| `/healthz`, `/next` (escaped redirect), `/fallback`, `/served-by` | none | nothing | as intended |
| `/proxy` (a request value in the URI of `ngx.location.capture`) | 731 | nothing | **missed** |
| `/ping-checked` (host validated with `string.match`, then `os.execute`) | none | 709 medium | **reported although safe** |
| `/kill` (`tonumber` and `%d`, then `os.execute`) | none | 701 low | **reported although safe** |

Why the three that differ, each pinned in the spec so it cannot change unnoticed:

- `/proxy` is a miss by design, not by accident: the registry models only the options table of
  `ngx.location.capture` (the CVE-2020-11724 request-framing defect), so a tainted subrequest
  URI in argument 1 is not a sink.
- `/ping-checked` is reported because luasec has no notion of a validating guard.
- `/kill` is a low-confidence 701 shape finding: a non-constant argument to `os.execute`, whatever
  made it safe.

Building this found a defect that is now fixed: a tainted `ngx.re.find` or `ngx.re.gsub` pattern was
reported as 728 **and** as a 709 "command execution" at certain confidence, for an API that executes
nothing (#310).

What is still not measured: handler bodies from real, deployed `.conf` files rather than from one
authored for the purpose, and any handler the author did not think of. The extractor itself is
exercised by `test/spec/nginxconf_spec.lua`.

## Result

620 findings over 707 files, 146 of them carrying at least one (20%), after nine
rounds of fixing false positives
that this corpus found, after the release review found more, and after 747 was
narrowed to the cases where a name and a value both say a credential is
embedded.

**#288** moved this number down by 525, and it is the only change recorded here
that has ever taken a finding away. 436 of them are 901/902/903 on files that are
not Lua at all — 94% of every parse and dialect failure this corpus produces, and
the single largest source of wrong numbers in the tool. The other 89 are real
detections inside the Lua that Test::Nginx specs carry in heredocs, which is a
coverage loss this change caused rather than a defect it fixed. **Every one of
the 525 is named in "What #288 took away" below**, because "the count went down
by 436" and "it went down by 436, of which 89 were FFI and command-execution
findings in nginx's own test suite" are different facts and only one of them
should be in the record.

**#262** moved this number, and not one finding of the increase is in code that
was already here. Six OpenResty repositories joined the corpus, pinned to
released tags; the four firmware entries were re-measured alongside them and came
out identical to main's, finding for finding and code for code. The split, the
representativeness question and what the new entries do and do not buy are in
"What #262 added, and what it did not" above. **What they buy is FFI and
crypto/encoding false-positive surface, not request-handler flow** — they
contribute nothing to 704, 708, 709, 710, 712 or 724, because a library is not a
request handler. A large share of the findings they added were in files that are
not Lua at all, which was #288 and is now fixed rather than caveated.

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

## What #288 took away

525 findings, 1136 → 611, and this is the only entry in this document that takes
any away. Both halves are named, because the honest version of this section is
not "the walker got fixed" and it is not "436 noise findings went away" either.

### The control: the four entries that were already here did not move

| | before | after |
| --- | --- | --- |
| `luci`, `luci-1806`, `openwrt-packages`, `luajit` | 248 | **248** |
| 701 | 49 | **49** |
| 708 | 22 | **22** |
| 709 | 23 | **23** |
| 901 | 10 | **10** |
| 903 | 20 | **20** |

Identical for every code, not only these: `luci` 32, `luci-1806` 153, `luajit` 63
and `openwrt-packages` 0, finding for finding and line for line. Those four carry
no `.t` file and no `.git`, which is exactly why they are the control — if a rule
had changed rather than a file selection, this table is where it would show.

### The 436 that were never information

All 436 are 901/902/903, and none is on a file that is Lua:

| On what | 901 | 902 | 903 | total |
| --- | --- | --- | --- | --- |
| 250 Test::Nginx `.t` specs, which are Perl | 250 | 6 | 171 | 427 |
| 2 `.git/packed-refs` | 2 | 0 | 0 | 2 |
| `lua-nginx-module/util/gen-lexer-c`, a C program | 1 | 0 | 1 | 2 |
| `lua-resty-jwt/ci`, `ci-coverage`, shell scripts | 2 | 0 | 0 | 2 |
| `luasocket/makefile.dist` | 1 | 0 | 0 | 1 |
| `luasocket/test/cgi/cat`, a shell script | 1 | 0 | 0 | 1 |
| `lua-nginx-module/tapset/ngx_lua.stp`, a probe | 1 | 0 | 0 | 1 |

This is the whole of the 901/902/903 the corpus produces now except the 30 that
are real: 10 parse failures and 20 dialect mismatches, all in `luajit`, all
predating #262.

### The 89 that were real, and what this cost

**These are genuine detections inside Lua that Test::Nginx specs carry in heredocs,
and this change removed them.** luasec lexed the whole Perl file and the tokens
inside `--- response` and `--- config` blocks are the Lua the spec actually runs,
so `ffi.cdef` inside a heredoc is the same `ffi.cdef` the tool reports everywhere
else. Excluding `.t` gave them up. Every one, by code and file:

| Code | Count | Files |
| --- | --- | --- |
| 707 FFI escape | 55 | `lua-nginx-module/t/099-c-api.t` 27, `t/146-malloc-trim.t` 9, `t/192-lua-block-conf-dump.t` 3, `t/138-balancer.t` 3, `t/025-codecache.t` 1, `lua-resty-core/t/pipe.t` 6, `t/socket-tcp-setoption.t` 4, `t/require.t` 2 |
| 701 shape-only | 17 | `lua-nginx-module/t/063-abort.t` 9, `t/163-signal.t` 3, `t/153-semaphore-hup.t` 1, `lua-resty-core/t/pipe.t` 2, `t/pipe-stdout.t` 1, `t/stream/process-type-hup.t` 1 |
| 711 backtick shell | 6 | `lua-nginx-module/t/060-lua-memcached.t` 1, `t/061-lua-redis.t` 1, `t/191-pipe-proc-quic-close-crash.t` 1, `lua-resty-core/t/process-type-privileged-agent.t` 2, `t/stream/process-type-privileged-agent.t` 1 |
| 702 env manipulation | 5 | `lua-nginx-module/t/192-lua-block-conf-dump.t` 2, `t/159-sa-restart.t` 1, `lua-resty-core/t/ssl-session-fetch.t` 2 |
| 703 dynamic code | 5 | `lua-nginx-module/t/081-bytecode.t` 2, `t/002-content.t` 1, `t/023-rewrite/sanity.t` 1, `t/024-access/sanity.t` 1 |
| 705 dynamic require | 1 | `lua-nginx-module/t/086-init-by.t` 1 |

Of the 711 row, all 6 were **false** — `my $pwd = \`pwd\`;` is a Perl backtick in
a Perl harness, and the row is now 0 for the reason it should be. Of the 707, 701,
702, 703 and 705 rows, **all 83 were real**: 55 FFI uses of `ngx_http_lua_shared_dict_get`,
`ngx_http_lua_find_zone`, `ffi.cdef`, `ffi.string`, `ffi.C.malloc`/`free`, and 17
`os.execute`/`io.popen` calls on arguments the file cannot fold. They are gone from
this table because the file they live in is Perl and the walker no longer claims
otherwise.

**This is a regression my own fix caused, stated as one rather than absorbed into
the total.** The trade is 436 findings that were never information for 83 that
were, and the right side of that trade is still the right side: 436 findings that
say "this is not Lua" from a tool that said "this is Lua" teach a reader nothing
and cost a security tool its credibility on every other row. But the cost is real
and it is not recovered by this change. Reading the Lua out of Test::Nginx heredocs
is a capability rather than a file-type fix, it is filed as **#291**, and it is the
one thing in this document that would bring any of the 83 back.

### What this does to `lua-nginx-module`

It contributes **zero findings now**, down from 377, because its four `.lua` files
never carried any. That is the honest answer to "is its `.t` surface worth keeping
now that #288 makes it real rather than accidental": it was worth having while it
was noise, because 377 findings in an entry are measurement even when they are the
wrong measurement, and 250 Perl files parsed as Lua is what finally made the walker
defect visible. It is not worth keeping now that it is accurate, because an entry
that measures nothing falsifies nothing. The replacement is the gap this queue has
named since #262 — a deployed `nginx.conf` with a `content_by_lua_block` — and
nothing upstream ships one to clone.



Hand-audited sample by code:

| Code | Count | Assessment |
| --- | --- | --- |
| 724 RPC handler | 25 | true, at two strengths. The rule that matters most after 709, and the one the release review found crashing on every controller with a non-hook field. Down 3 from 28 with #226: the three controller methods that now carry a real flow to their sink (`startstop`, `lxc_create`, `iface_reconnect`) report a 709 instead of the weaker "exposed, nothing feeds it". Unmoved in count by #238 and down 17 in severity: 17 of the 25 are a CBI hook running a literal command, which is this corpus's spelling of "restart this service", and they now report at `medium`/low confidence instead of `high`. The 8 that stay `high` all reach a sink whose command is built from something that does not fold - `ddns`'s `CTRL.luci_helper` is the clearest - and they keep the registered severity |
| 708 exposed sink | 21 | mostly true: an exported function in a LuCI library calls an execution sink and nothing in that file feeds it. Fixed after review: it was also firing on functions the file itself called, and its registry message, doc row and registered severity disagreed. Down 3 from 36 with #226, for the same reason 724 fell: three exported functions now carry a named flow to their sink. Unmoved again in #225 - the fix there stopped it *replacing* the 701 at the sink it names, so the same sinks are reported and most of them now carry their 701 as well. Down 2 with #281, from `ccache.lua`'s `_load_sane`, which is a `local function` whose only call - `local modcons = _load_sane(encoded)` - was invisible to `callgraph.call_sites` because it is an assignment and not a whole statement, so the file read as one that never fed it. #281 also *tightened* this rule rather than only widening it: a resolved call now withholds 708 only when it passes an argument the file cannot fold to a constant, because for an exported handler - whose real callers are in another file, since LuCI registers it by name - an in-file call proves nothing about the path an attacker would take. Under the looser rule `luci-splash`'s `call(cmd)`, which `os.execute`s its argument and is called twice with string literals, lost its 708 and gained no 709, which is silence on a reachable sink; the tightened rule keeps it Down 1 with #309: `admin_network/wifi.lua:85` is fed by a `formvalue` now, so it is the 709 at `:103` instead. |
| 747 hardcoded secret | 15 | was 17 and every one of the 17 was a false positive; see below. It then went to 0 and came back as 2, because widening it to the forms firmware actually uses — a `uci.set` key argument, a CBI `.default`/`.value` field, a value concatenated at author time — also made it read `public_key.datatype = "and(base64,rangelength(44,44))"`, a CBI validator expression on a field that happens to be named after a credential. Those 2 are gone: only the fields that carry a value count, and only the profile-declared writers and real UCI cursors count as config writes. The rule's true positives are all fixtures, because the four firmware entries contain no hardcoded credential. **#262 moved this off zero, and every one of the 15 is a false positive** — see below. **#290 left the count at 15 and moved every one of them to `low`**, which is the whole of that change on this corpus and the reason its table and its golden file did not move: fourteen sit in `corpus/luasocket/test/`, where they are a URL parser's own parse fixtures, and one is at `corpus/luasocket/src/ftp.lua:30`, the default an anonymous FTP login sends. |
| 730 open redirect / header injection | 3 | New with #296 (absent before, so it was not in the table): all three are in the authored `openresty-authored/nginx.conf`, and all three are what the handler was written to contain: `/go` (`ngx.redirect` of a query argument, certain), `/forward-host` (`ngx.req.set_header` from a request header, certain) and `/cache-key` (`ngx.header[...] = ngx.var.uri`, medium). The real corpus has no 730: the OpenResty entries are libraries, not handlers. |
| 901 parse failure | 10 | true for the ten that were here before #262: real Lua the parser still rejects, all in `luajit`. Four of the original 14 (gettext escapes such as `"\$"`, which Lua 5.1 accepts) now parse through the escape retry (#181) and are analysed. #262 added 258 more and **all 258 were files that are not Lua at all** — 250 Test::Nginx `.t` specs written in Perl, 2 `.git/packed-refs`, a `.stp` probe, a Makefile, two shell scripts and a C program — which the walk selected and the parser then correctly could not read. **#288 took all 258 back**, and this row is the ten it always was. |
| 727 unbounded growth | 16 | true after narrowing: string accumulation in a loop with no visible ceiling. Up 2 with #262, both in `luasocket`. |
| 707 FFI escape | 346 | true: LuaJIT source, and with #262 the first non-LuaJIT FFI in the corpus Up hard with #262, which added `lua-resty-core` — **that entry is the FFI layer the `ngx.*` API is built on, so it is FFI by construction**, and 337 of the increase are its `.lua` files. The OpenResty entries are the first thing this corpus has contained that this rule could be checked against at all; before them this row was LuaJIT only. **Down 55 with #288, and this is the one row where that change cost something real**: all 55 are `ffi.cdef`, `ffi.string`, `ffi.C.malloc`/`free`, `ffi.C.ngx_http_lua_shared_dict_get` and `ffi.C.ngx_http_lua_find_zone` inside the `--- response` heredocs of Test::Nginx specs in `lua-nginx-module` and `lua-resty-core`. They were found only because luasec lexed a Perl file end to end, and they are named one file at a time in "What #288 took away". 327 of the 346 that remain are `lua-resty-core`'s and `lua-resty-jwt`'s own `.lua` files. |
| 903 dialect mismatch | 20 | Down from 192 with #288: the 172 #262 added were Test::Nginx `.t` specs and a C lexer generator the walk read as Lua. What remains is the ten that predate #262 - 5.3 bitwise operators under `--std luajit`, still mislabelled. |
| 741 obfuscated loader | 0 | was 5, and all 5 were false. Down 2 with #235: `luci-base`'s `cbi.lua` defines `load` as its own module loader over `loadfile`, so `load(node, name)` at line 581 is module loading, not a hidden payload. Down 2 more with #256: `defined_function` resolved local bindings only, so a **global function statement the file defines** had no binding to follow and the walk could not read it. `luadoc`'s `lp.lua:104` is `loadstring(translate(s))` where `translate` is defined 61 lines earlier as a global `function translate(s)` and only rewrites template markup — one site, counted twice because the corpus holds two checkouts of openluci/luci (`corpus/luci` and `corpus/luci-1806`) and `lp.lua` is byte-identical between them (`cmp` clean). The same double-counting is why #235's drop was 2 and not 1: the CBI file appears in both checkouts, as `luci-base` in one and `luci-compat` in the other. **The 1 that remains is a different defect and is still wrong.** `genlibbc.lua:145` is the LuaJIT build tool handing the output of `transform_lua` to the standard `load`. It is not the #256 class: `transform_lua` is a `local function` (`genlibbc.lua:48`), which `defined_function` already resolved — the finding comes from `shape_of` reading `string.gsub(code, "PAIRS%((.-)%)", function(var) ... end)` inside it as a substitution decode, and that shape is a real decoder shape rather than a gap. So the column was 5 findings over 3 sites before #235, 3 over 2 after it, and 1 over 1 after #256 |
| 709 injection | 34 | true, and the one that matters. Up from 5 with #226, which modelled the arguments `luci.dispatcher` calls a controller method with — the LuCI handlers this corpus is full of were previously reported as "exposed, nothing feeds it". Nine of the twelve are sites that carried a shape-only 701/702 instead (`adblock:75`, `cshark:56`, `diag:36`, `mwan3:102`, `network:302`, `network:412`, `status:65`, `status:85`, `system:183`); three are flows nothing reported at all before (`ddns:310`, `lxc:70`, `network:272`). All twelve name their source, and all twelve are `medium`: an entry point makes an argument reachable, it does not prove the dispatcher that reaches it is itself reachable. Up 5 more with #265, which declared the shell form of `nixio.exec` (`admin/system.lua:416` and `:446`, `mini/system.lua:233`, `failsafe/failsafe.lua:170` and `:200`) — five call sites, five findings, none of which was previously reported by any code. Up 1 more with #268, which declared the other two functions nixio's process module exports (`nixio.execp` and `nixio.exece`): `luci-app-nlbwmon/luasrc/controller/nlbw.lua:46`, where the archive entry names read out of an uploaded backup by `io.popen("/bin/tar -tzf %s" % tmp)` at `:179` reach `execve("/bin/tar", {..., unpack(files)})` at `:207`. The pre-existing five are unchanged, including the two from #58 (`cshark.lua:73`, `wol.lua:85`) Up 4 with #309: three CBI flows now name `luci.cbi.formvalue` or a `validate` argument as their source (`ddns/detail.lua:126`, `:1185`, `:1260`) and `admin_network/wifi.lua:103`, where the `formvalue` is wrapped in `ut.shellquote` and is reported one step lower with `sanitizer: shell-quoted`, as every quoted flow is. No 709 already reported moved. Up 2 with #317/#309: `commands.lua:163` and `:220`, the two `table.concat(argv, " ")` commands in `luci-app-commands`, whose `argv` is built by appending the elements of `parse_args(luci.http.urldecode(args))` -- the URL path the dispatcher passes in. Both are `medium` and name an entry point as the source; the one named is `putstr`, because the controller std's `*` entry makes every function in a controller file an entry and the earliest source by line is reported, but the flow is checked from the dispatcher's `...` as well (`action_run(...)` -> `execute_command(callback, ...)` -> `parse_cmdline(...)`). These were 701 and 702 at `low`, which is why those rows fell. `ddns/detail.lua:439`, `:867` and `:918` are not here: the value passes through `DDNS.parse_url`, defined in `luci/tools/ddns.lua`, and a default scan reads one file at a time. Under `--whole-program` they are 709 too (`medium`, source `uurl.validate`, `iurl4.validate`, `iurl6.validate`), and nothing else in the corpus moves; that run is not the golden's. Up 5 with #296, all in the authored `openresty-authored/nginx.conf`, all intended: `/handoff` (`ngx.exec`, line 41), `/ping` (89), `/ping-checked` (100), `/dns` (116), `/run` (126). `/ping-checked` is the one false positive of the five (the host is validated with `string.match` first, and luasec has no notion of a validating guard); the other four are the flow the handler was written to contain. |
| 701 shape-only | 46 | Down 4 with #309, which declared the CBI `formvalue` method and the `validate`/`write` callbacks of a `model/cbi` file as request data: `ddns/detail.lua:126`, `:1185` and `:1260` and `admin_network/wifi.lua:103` became 709s. Down 17 with #288, all in Test::Nginx `.t` specs (#291) - real detections in Lua embedded in Perl; the loss is recorded there, not absorbed here. Down 1 with #317/#309: `commands.lua:163` (`os.execute(table.concat(argv, " "))`, `argv` filled by `argv[#argv+1] = v` in a loop over a parsed argument list) is a 709 now; see 709. Up 1 with #296: `openresty-authored/nginx.conf:108`, `os.execute` of a `tonumber`/`%d`-checked value, a low-confidence shape finding on a handler that is safe (a known false positive, named in the authored-conf section). |
| 703 file write | 19 | Down 5 with #288, all in Test::Nginx `.t` specs (#291), the same recorded loss. Down 1 with #317: `luajit/src/host/genlibbc.lua:145`'s `load(tcode, ...)` is a 710 now (see 710); the label on this row is the older catalogue's, as for 702. |
| 702 env manipulation | 13 | Down 5 with #288, all in Test::Nginx `.t` specs (#291). Down 1 with #317/#309: `commands.lua:220` (`io.popen(table.concat(argv, " ") ...)`, the same `argv`) is a 709 now. |
| 704 dynamic load | 21 | true: `dofile`/`loadfile`/`load` of a path the file cannot fold to a constant, including calls whose result is used. Up 4 from 17 with #225, for the same reason as 701: four dynamic loads inside exported functions were being masked by the 708 at the same sink. (The neighbouring 703 and 702 rows carry labels from an older catalogue; the counts are the measured ones and those two labels are a separate fix.) |
| 705 dynamic require | 22 | Down 1 with #288, in a Test::Nginx `.t` spec (#291). |
| 710 dynamic code | 2 | true by the rule, low real risk: `luajit/dynasm/dynasm.lua:626` compiles a file it read (`loadstring(s)` of `io.open(...):read`); a file read is untrusted by rule, and this is a build-time tool Up 1 with #317: `luajit/src/host/genlibbc.lua:145` loads Lua extracted by `string.gmatch` from a C source file it read (`for name, code in string.gmatch(src, ...)`, `load(tcode, "", mode)`); the `for` names now carry the taint of what they iterate, so this is a 710 at `medium` instead of a 703 at `low`. True by the rule, no real risk: a build tool reading its own source tree. |
| 712 partial quote | 3 | true: a shell-quoted argument alongside an unquoted one, where the partially-quoted call is used in an expression. Up 2 from 1 with #226: at `diag:36` and `network:412` the tool can now see both halves of the command, so it reports which part was quoted |
| 725 env escape | 2 | true after 725 was narrowed from every setfenv to the dangerous ones. Up 1 with #262: `lua-resty-jwt`'s `lib/resty/jwt-validators.lua`, which replaces an environment for a claim-validation closure |
| 728 search pattern | 2 | one of two. The first, and the only one in a real library: `lua-resty-jwt`'s `lib/resty/jwt-validators.lua:93`, `string.match(val, pattern)` inside `string_match_function`. That function is reached from `opt_check(pattern, ...)` and `opt_any_of(patterns, ...)` — the `pattern` is supplied by the *application's own* `jwt:verify()` options, and `val` is the claim out of the token. Reported as untrusted data used as a search pattern, the untrusted argument is the one being matched, not the one being matched against. The class is real — `string.match` does treat its second argument as a pattern — but this instance is the rule binding to the wrong parameter, and it is in the one entry added for exactly this shape Up 1 with #296: `openresty-authored/nginx.conf:134`, `ngx.re.find(ngx.var.uri, pattern, "jo")` with `pattern` from a query argument, the handler written to contain it. That is the first 728 in the corpus on a request handler, not a library. |
| 711 backtick shell | 0 | **Now 0.** All 6 were Perl backticks inside Test::Nginx `.t` specs the walk read as Lua; #288 stopped reading them. There was never a real finding here. |
| 902 unsupported dialect | 0 | **Now 0.** All 6 were Test::Nginx `.t` specs - a Perl file cannot be an unsupported Lua dialect. |

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

What the new corpus asked of 747 was concrete, and #262 could not answer it
because that issue owns no rule: **a value that is a placeholder, or that is a
protocol default rather than a chosen credential, should not be reported at
`high`.** `"password"`, `"pass?#wd"` and the anonymous FTP default were all
reportable-but-not-leaked. **#290 answers it, by demotion rather than by
suppression**, and the distinction matters for the next reader: a demotion is a
statement about *exposure*, so all 15 are still reported and
`luasec --only 747` still finds them - only the severity moved, which is why the
count in the table above is unchanged.

Two contexts demote, and the two are answered from opposite directions. One is
the **file**: a path segment named `test`, `tests`, `spec`, `specs` or `t`, or a
file whose own name begins or ends with one, is a test suite, and a
credential-shaped literal in a test suite is the fixture it is. That is the blunt
route and it is the one that carries the corpus's fourteen. The macOS scratch
directory is answered by excluding temporary roots as absolute prefixes of the
resolved path (`/var/folders/`, `/private/var/folders/`, `/tmp/`,
`/private/tmp/`, and `$TMPDIR` when it is set), **not** by leaving `t/` out of
that vocabulary. `t/` is how OpenResty and Test::Nginx spell a test suite, and
"buys nothing in this corpus" is an argument about the corpus rather than about
the rule, which ships to scan trees nobody here has cloned. Neither change moves
the count in the table above: this corpus has no `.lua` file under a `t/`
directory, and none of the 15 is under a temporary root. The other context is
the **value**, and it is where the one in `src/` went: a strong `password` name
holding `anonymous@anonymous.org` is the identity an anonymous login sends
instead of a password somebody chose.

That second one splits its two halves, in opposite directions. The **domain** is
a shape and not a list: the issue called the constant an RFC-mandated default and
named RFC 2577; RFC 2577 is *FTP Security Considerations*, an Informational memo
about the bounce attack and brute-force limits, and it says nothing about an
anonymous login. There is no IETF RFC for the convention - it is de-facto,
documented in `ftp(1)`, and every client implements it. So a table of permitted
domains would have had no authority to copy from, and the only string in it that
catches this corpus is `anonymous@anonymous.org`, which is *luasocket's* choice
of domain. A shape - either nothing after the `@` or a domain whose last label is
letters - covers every client's choice at once and has nothing to go stale. The
**local part** is the other way round, and is a list of five (`anonymous`,
`anon`, `ftp`, `guest`, `nobody`), because there are a handful of anonymous
account names and no more, while `admin`, `svc-deploy` and `jenkins` are three
accounts on three real systems and the next one is nobody's to enumerate. The
first #290 draft made the local part a shape too and demoted every
address-shaped password in the world; `password = "svc-deploy@staging.acme.com"`
is a chosen credential, and lowering it moves the finding in the one direction a
security tool may not.

The other route the issue offered, placement - a literal in a field named
`password` inside a table that is clearly a fixture - was **not** taken, and the
measurement is why it could not be: `{scheme = "ftp", host = ..., user = ...,
password = ...}` is byte for byte how firmware writes an FTP connection
configuration, and nothing in the table says which of the two it is. The path
says it, the table does not.

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
