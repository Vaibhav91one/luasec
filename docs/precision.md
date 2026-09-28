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

178 findings over 566 files (31%), after four rounds of fixing false positives
that this corpus found. Hand-audited sample by code:

| Code | Count | Assessment |
| --- | --- | --- |
| 708 exposed sink | 37 | mostly true: a named function in a LuCI library calls `sys.exec` or `nixio.process` and something outside the file feeds it |
| 747 hardcoded secret | 17 | **false positives**: PEM header markers (`"-----BEGIN RSA PRIVATE KEY-----"`) and `depends({auth = "EAP-TLS"})`, where the name looks secret and the value is not |
| 901 parse failure | 14 | true: real Lua using gettext escapes (`"\$"`, `"\+"`) that a 5.4 parser rejects. A dialect gap, honestly reported |
| 727 unbounded growth | 12 | true after narrowing: string accumulation in a loop with no visible ceiling |
| 707 FFI escape | 9 | true: LuaJIT source |
| 903 dialect mismatch | 7 | true: 5.3 shift operators under `--std luajit`, which does not have them |
| 741 obfuscated loader | 5 | true: a decoder feeding `loadstring` |
| 709 injection | 1 | true, and the one that matters |

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

Two more came from reading the findings rather than the rules:

5. **Constant folding silently failed on numbers.** The parser keeps a number's
   source text, so `1` folded to the string `"1"`. Arithmetic never folded, and a
   number compared equal to its own text.
6. **The rule context resolved only literal callee paths.** `local sys =
   require("luci.sys")` then `sys.exec(...)` was invisible to every rule module,
   so a real LuCI handler produced nothing. It now shares the engine's
   alias-aware resolver, and prunes function bodies from their definitions so
   each call is visited once.

## What is still noisy

747 is the weakest rule in the catalogue: on this corpus every finding was a
false positive. It needs a value that looks like a secret (length, character
class) and a name list that drops bare `key` and `auth`, which are as often
protocol names as credentials.
