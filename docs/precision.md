# Measured precision

Numbers here are measurements against real firmware Lua, not against the test
fixtures. The corpora are cloned by `make corpus` and are gitignored.

## The corpora

| Corpus | Files collected | What it is |
| --- | --- | --- |
| `corpus/luci` | 73 | current LuCI libraries |
| `corpus/luci-1806` | 460 | LuCI at commit `20b3600d` on the `openwrt-18.06` branch: the `.lua` web layer, written as root-executing CGI |
| `corpus/luajit` | 29 | LuaJIT, the dialect firmware vendors use for speed |
| **total** | **562** | |

`make corpus` clones four repositories. Three of them contribute the `.lua` files
counted above; the fourth is the OpenWrt package tree, which contributes none and
is scanned only because it is the smaller script tree worth watching. The 18.06 tree is pinned rather than tracked, because a
measurement against a moving branch is not a measurement: the commit is named so
a reader can tell whether they are looking at the same code.

562 is how many `.lua` files `make corpus` collects. 566 is how many paths
luasec selects from them and analyzes, the difference being the extensionless
CGI handlers and generated scripts a firmware image carries. The headline counts
what was analyzed, because that is what produced the findings.

Command:

```sh
bin/luasec --std +openwrt+luci+luajit --format json -o /tmp/corpus.json corpus
```

## Result

257 findings over 566 files, 101 of them carrying at least one (18%), after six
rounds of fixing false positives
that this corpus found, after the release review found more, and after 747 was
narrowed to the cases where a name and a value both say a credential is
embedded.

Two changes moved this number since the last release, and neither is a
regression.

**#243** folded a local whose only definition is a constant, so a `701` no
longer fires on `local CMD = "literal"` reaching a sink. Four findings left
and none arrived, all four of them `high`. They were constants in real LuCI
source: three in `luci-app-dnscrypt-proxy`, building a command from `res_input`
and `url`, both module-local literals assigned once, and one in
`luci-mod-admin-mini`, handing `io.popen` a `restore_cmd` written out as a
literal three lines above the call. No taint code moved, which is the part that
matters: this removed shape noise from values that could not have carried
attacker input, and changed nothing else.

This is a different change from retiring the suppressions it makes redundant.
The `701` directives in `cli/menu.lua` can now be deleted, and deleting them
moves no number, because the findings are already gone. Two changes, two PRs,
and only this one moves the measurement.

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
exposure. 708 falls by one, to 32, because the fix is that it no longer
*replaces* the sink report rather than that it reports less. Three of the sites
#225 restores were also among the nine #226 turned into a 709, which is why
this reads 29 where #225 measured 32 against the previous main. No file that
was clean became dirty.

This number has been wrong three times, each time because the headline was
edited by hand and the per-code table was not. `test/spec/precision_spec.lua`
now parses this file, sums the per-code counts, and fails the build if the
headline and the table disagree, so the two cannot drift apart again. The
command above is here so the number can be reproduced rather than believed.



Hand-audited sample by code:

| Code | Count | Assessment |
| --- | --- | --- |
| 724 RPC handler | 25 | true: a LuCI controller method that reaches an execution sink and is dispatched from a page. The rule that matters most after 709, and the one the release review found crashing on every controller with a non-hook field. Down 3 from 28 with #226: the three controller methods that now carry a real flow to their sink (`startstop`, `lxc_create`, `iface_reconnect`) report a 709 instead of the weaker "exposed, nothing feeds it" |
| 708 exposed sink | 32 | mostly true: an exported function in a LuCI library calls an execution sink and nothing in that file feeds it. Fixed after review: it was also firing on functions the file itself called, and its registry message, doc row and registered severity disagreed. Down 3 from 36 with #226, for the same reason 724 fell: three exported functions now carry a named flow to their sink. Unmoved again in #225 - the fix there stopped it *replacing* the 701 at the sink it names, so the same sinks are reported and most of them now carry their 701 as well. Down 1 to 32 with #243, which folded the constant its one argument was built from |
| 747 hardcoded secret | 0 | was 17 and every one of the 17 was a false positive; see below. It then went to 0 and came back as 2, because widening it to the forms firmware actually uses — a `uci.set` key argument, a CBI `.default`/`.value` field, a value concatenated at author time — also made it read `public_key.datatype = "and(base64,rangelength(44,44))"`, a CBI validator expression on a field that happens to be named after a credential. Those 2 are gone: only the fields that carry a value count, and only the profile-declared writers and real UCI cursors count as config writes. The rule's true positives are all fixtures, because this corpus contains no hardcoded credential |
| 901 parse failure | 10 | true: real Lua the parser still rejects. Four of the original 14 (gettext escapes such as `"\$"`, which Lua 5.1 accepts) now parse through the escape retry (#181) and are analysed |
| 727 unbounded growth | 14 | true after narrowing: string accumulation in a loop with no visible ceiling |
| 707 FFI escape | 9 | true: LuaJIT source |
| 903 dialect mismatch | 20 | true but mislabelled: all 20 are the 5.3 bitwise operators under `--std luajit`, and the message calls an operator an API |
| 741 obfuscated loader | 5 | true: a decoder feeding `loadstring` |
| 709 injection | 17 | true, and the one that matters. Up from 5 with #226, which modelled the arguments `luci.dispatcher` calls a controller method with — the LuCI handlers this corpus is full of were previously reported as "exposed, nothing feeds it". Nine of the twelve are sites that carried a shape-only 701/702 instead (`adblock:75`, `cshark:56`, `diag:36`, `mwan3:102`, `network:302`, `network:412`, `status:65`, `status:85`, `system:183`); three are flows nothing reported at all before (`ddns:310`, `lxc:70`, `network:272`). All twelve name their source, and all twelve are `medium`: an entry point makes an argument reachable, it does not prove the dispatcher that reaches it is itself reachable. The pre-existing five are unchanged, including the two from #58 (`cshark.lua:73`, `wol.lua:85`) |
| 701 shape-only | 49 | true: a sink whose argument the analyzer could not trace, including sinks whose result is used (assigned to a local, passed to another call, or wrapped in an expression) that were previously invisible because only bare statement-level calls were checked. Down 3 to 22 with #226, then up to 51 with #225: that is where this row stops being an undercount. An exported sink used to be reported as a 708 *instead of* its 701, and 29 of these are the ones that suppression was eating. Each one is the same shape-only finding the tool already reports in the same file when the sink is not exported, and no file that was clean became dirty. Down 2 to 49 with #243: two sites in `luci-app-dnscrypt-proxy` were building a command from module-local literals `res_input` and `url`, which the fold now resolves |
| 703 file write | 17 | true: writes outside /tmp and /var/run, including sinks nested in expressions |
| 702 env manipulation | 14 | true: setfenv grants and _G metatables, including sinks whose result is used in an expression. Down 6 from 21 with #226: those six sites now report a 709 naming the source. Down 1 to 14 with #243: `luci-mod-admin-mini`'s `system.lua` hands `io.popen` a `restore_cmd` that is a literal on line 18 |
| 704 dynamic load | 21 | true: `dofile`/`loadfile`/`load` of a path the file cannot fold to a constant, including calls whose result is used. Up 4 from 17 with #225, for the same reason as 701: four dynamic loads inside exported functions were being masked by the 708 at the same sink. (The neighbouring 703 and 702 rows carry labels from an older catalogue; the counts are the measured ones and those two labels are a separate fix.) |
| 705 dynamic require | 19 | true after the rule was un-inverted; see below. Now also catches dynamic require in a local assignment |
| 710 dynamic code | 1 | true by the rule, low real risk: `luajit/dynasm/dynasm.lua:626` compiles a file it read (`loadstring(s)` of `io.open(...):read`); a file read is untrusted by rule, and this is a build-time tool |
| 712 partial quote | 3 | true: a shell-quoted argument alongside an unquoted one, where the partially-quoted call is used in an expression. Up 2 from 1 with #226: at `diag:36` and `network:412` the tool can now see both halves of the command, so it reports which part was quoted |
| 725 env escape | 1 | true after 725 was narrowed from every setfenv to the dangerous ones |

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

Measured after the change, same command as everywhere else in this file:

```sh
bin/luasec --std +openwrt+luci+luajit --format json -o /tmp/secrets-after.json corpus
jq -r '[.findings[] | select(.code=="747")] | length' /tmp/secrets-after.json
# 0
```

0 findings over 562 files. **That is not a precision figure: with nothing
reported there is no denominator, and a rule that finds nothing is as wrong as
one that finds everything.** The 562-file corpus is upstream LuCI (two revisions) and LuaJIT,
which ships no hardcoded credential for this rule to find, so the true
positives are covered by fixtures that are asserted one by one: a router script
shipping `ADMIN_PASSWORD = "admin"`, a WiFi generator shipping a PSK, an
`API_TOKEN`, a complete private key block, and a PEM body beside its header.
Four of the five are found at `high` confidence; the bare `key` beside a
six-digit hex value is found at `low`. The fixtures, not the corpus, are what
proves the rule still works.

What 747 gives up, stated rather than hidden: a bare `key` or `auth` holding
something under twelve characters, or a single lower-case word with no digit in
it, is not reported. `key = "timeout_ms"` and `auth = "EAP-TLS"` are silence
rather than a finding, and that is the trade - a bare name plus a bare word is a
table index about as often as it is a credential, and it was 100% wrong in this
corpus. Naming the value in a qualifying name gets the report either way.

### Still noisy, and not in this branch

- **903 is true but mislabelled.** All 20 findings are the 5.3 bitwise
  operators under `--std luajit`, and the message calls an operator an API. The
  findings are honest about the file; the sentence about it is not.
- **901 is a dialect gap, not a defect in the code.** 10 files still fail to
  parse. Four more used gettext escapes (`"\$"`, `"\+"`) that Lua 5.1
  accepts and the parser rejected; since #181 they are parsed again with the
  escape rewritten to one of the same length and analysed. The rest are
  reported rather than guessed at, which is the right behaviour, but it is 10
  findings an operator has to learn to read.
- **708 is 32 findings and "mostly true" is not a number.** The claim has not
  been re-audited since the review fix.
