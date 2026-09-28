# Measured precision

Numbers here are measurements against real firmware Lua, not against the test
fixtures. The corpora are cloned by `make corpus` and are gitignored.

## The corpora

| Corpus | Files collected | What it is |
| --- | --- | --- |
| `corpus/luci` | 73 | current LuCI libraries |
| `corpus/luci-1806` | 460 | LuCI at the pinned `openwrt-18.06` branch: the `.lua` web layer, written as root-executing CGI |
| `corpus/luajit` | 29 | LuaJIT, the dialect firmware vendors use for speed |
| **total** | **562** | |

`make corpus` clones all three, so the numbers below are reproducible with the
command above. The 18.06 tree is pinned rather than tracked, because a
measurement against a moving branch is not a measurement: the commit is named so
a reader can tell whether they are looking at the same code.

Command:

```sh
bin/luasec --std +openwrt+luci+luajit --format json -o /tmp/corpus.json corpus
```

## Result

146 findings over 562 files, 74 of them carrying at least one (13%), after six
rounds of fixing false positives
that this corpus found, after the release review found more, and after 747 was
narrowed to the cases where a name and a value both say a credential is
embedded.

This number has been wrong three times, each time because the headline was
edited by hand and the per-code table was not. `test/spec/precision_spec.lua`
now parses this file, sums the per-code counts, and fails the build if the
headline and the table disagree, so the two cannot drift apart again. The
command above is here so the number can be reproduced rather than believed.



Hand-audited sample by code:

| Code | Count | Assessment |
| --- | --- | --- |
| 724 RPC handler | 27 | true: a LuCI controller method that reaches an execution sink and is dispatched from a page. The rule that matters most after 709, and the one the release review found crashing on every controller with a non-hook field |
| 708 exposed sink | 36 | mostly true: an exported function in a LuCI library calls an execution sink and nothing in that file feeds it. Fixed after review: it was also firing on functions the file itself called, and its registry message, doc row and registered severity disagreed |
| 747 hardcoded secret | 0 | was 17 and every one of the 17 was a false positive; see below. It then went to 0 and came back as 2, because widening it to the forms firmware actually uses — a `uci.set` key argument, a CBI `.default`/`.value` field, a value concatenated at author time — also made it read `public_key.datatype = "and(base64,rangelength(44,44))"`, a CBI validator expression on a field that happens to be named after a credential. Those 2 are gone: only the fields that carry a value count, and only the profile-declared writers and real UCI cursors count as config writes. The rule's true positives are all fixtures, because this corpus contains no hardcoded credential |
| 901 parse failure | 14 | true: real Lua using gettext escapes (`"\$"`, `"\+"`) that a 5.4 parser rejects. A dialect gap, honestly reported |
| 727 unbounded growth | 12 | true after narrowing: string accumulation in a loop with no visible ceiling |
| 707 FFI escape | 9 | true: LuaJIT source |
| 903 dialect mismatch | 20 | true but mislabelled: all 20 are the 5.3 bitwise operators under `--std luajit`, and the message calls an operator an API |
| 741 obfuscated loader | 5 | true: a decoder feeding `loadstring` |
| 709 injection | 3 | true, and the one that matters |
| 701 shape-only | 3 | true: a sink whose argument the analyzer could not trace |
| 703 file write | 6 | true: writes outside /tmp and /var/run |
| 702 env manipulation | 4 | true: setfenv grants and _G metatables |
| 704 unencrypted transport | 1 | true: a request body over plain HTTP |
| 705 dynamic require | 5 | true after the rule was un-inverted; see below |
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
- **901 is a dialect gap, not a defect in the code.** 14 files use gettext
  escapes (`"\$"`, `"\+"`) that a 5.4 parser rejects. Reported rather than
  guessed at, which is the right behaviour, but it is 14 findings an operator
  has to learn to read.
- **708 is 36 findings and "mostly true" is not a number.** The claim has not
  been re-audited since the review fix.
