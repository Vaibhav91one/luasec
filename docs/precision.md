# Measured precision

Numbers here are measurements against real firmware Lua, not against the test
fixtures. The corpora are cloned by `make corpus` and are gitignored.

## The corpora

| Corpus | Files collected | What it is |
| --- | --- | --- |
| `corpus/luci` | 73 | current LuCI libraries |
| `corpus/luci-1806` | 460 | LuCI at openwrt-18.06: the `.lua` web layer, written as root-executing CGI |
| `corpus/luajit` | 29 | LuaJIT, the dialect firmware vendors use for speed |
| **total** | **566** | |

Command:

```sh
bin/luasec --std +openwrt+luci+luajit --format json -o /tmp/corpus.json corpus
```

## Result

136 findings over 566 files (24%), after five rounds of fixing false positives
that this corpus found, and after the release review found more. An earlier
version of this document claimed 178; that number never added up, because the
per-code table below was audited correctly and only the headline was wrong. The
command is here so the number can be reproduced rather than believed.

Hand-audited sample by code:

| Code | Count | Assessment |
| --- | --- | --- |
| 708 exposed sink | 36 | mostly true: an exported function in a LuCI library calls an execution sink and nothing in that file feeds it. Fixed after review: it was also firing on functions the file itself called, and its registry message, doc row and registered severity disagreed |
| 747 hardcoded secret | 17 | **false positives**: PEM header markers (`"-----BEGIN RSA PRIVATE KEY-----"`) and `depends({auth = "EAP-TLS"})`, where the name looks secret and the value is not |
| 901 parse failure | 14 | true: real Lua using gettext escapes (`"\$"`, `"\+"`) that a 5.4 parser rejects. A dialect gap, honestly reported |
| 727 unbounded growth | 12 | true after narrowing: string accumulation in a loop with no visible ceiling |
| 707 FFI escape | 9 | true: LuaJIT source |
| 903 dialect mismatch | 20 | true but mislabelled: all 20 are the 5.3 bitwise operators under `--std luajit`, and the message calls an operator an API |
| 741 obfuscated loader | 5 | true: a decoder feeding `loadstring` |
| 709 injection | 3 | true, and the one that matters |
| 701 shape-only | 3 | true: a sink whose argument the analyzer could not trace |

## What the corpus fixed

Four defects that no fixture had caught, each of which was a large share of the
findings:

1. **The file walker treated a firmware tree as if it were all Lua.** `.patch`,
   `.pem`, `.js`, `.po`, `.awk`, `Makefile` and `.luadoc` were all scanned, because
   they begin with dashes and a Lua comment does too. 1404 files collected instead
   of 566, and 674 findings were all noise. Now an extension decides it when we
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

747 is the weakest rule in the catalogue: on this corpus every finding was a
false positive. It needs a value that looks like a secret (length, character
class) and a name list that drops bare `key` and `auth`, which are as often
protocol names as credentials.
