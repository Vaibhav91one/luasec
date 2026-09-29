# Rule catalogue

Every finding carries a stable three-digit code, a severity, a confidence and,
where one applies, a CWE reference. Each code has its own page under [docs/rules/](rules/), with an example, how to fix it, and a prompt you can hand to an AI coding agent.

The 0xx-6xx range is [luacheck](https://github.com/lunarmodules/luacheck)'s
vocabulary and a code in it is never reused here - a spec fails the build on a
collision with the reserved set. The one exception is `012`, which is luasec's
and was not always: the suppression-directive code sat on `021`, which is
luacheck's, so the same finding meant one thing in this report and another in
luacheck's.

Severity: `critical`, `high`, `medium`, `low`.
Confidence: `certain` (the data flow is unambiguous), `high`, `medium` (heuristic
default), `low` (shape only, no proven flow).

## 0xx - suppression

| Code | Severity | CWE | Meaning |
| --- | --- | --- | --- |
| 012 | low | CWE-0 | a `-- luasec:` suppression directive could not be read |

## 7xx - execution and dynamic code

| Code | Severity | CWE | Meaning |
| --- | --- | --- | --- |
| 701 | high | CWE-78 | command execution with a non-constant argument |
| 702 | high | CWE-78 | pipe opened with a non-constant command |
| 703 | high | CWE-94 | dynamic code evaluation with a non-constant argument |
| 704 | high | CWE-94 | code or script loaded from a non-constant path |
| 705 | high | CWE-94 | module name computed at runtime |
| 706 | high | CWE-94 | native library loaded from a non-constant path |
| 707 | high | CWE-94 | LuaJIT FFI escape hatch used |
| 708 | severity of the wrapped sink | CWE-78 | execution sink in an exported function that this file never calls and never feeds |
| 709 | critical | CWE-78 | untrusted data reaches command execution |
| 710 | critical | CWE-94 | untrusted data reaches dynamic code evaluation |
| 711 | high | CWE-78 | shell command written as a backtick literal |
| 712 | high | CWE-78 | shell metacharacters from untrusted data are not quoted |

## 7xx - firmware specific

| Code | Severity | CWE | Meaning |
| --- | --- | --- | --- |
| 721 | high | CWE-1236 | write to flash or firmware configuration with untrusted data |
| 722 | high | CWE-78 | configuration value set from untrusted data, later executed by a service |
| 723 | medium | CWE-538 | sensitive file read by path literal |
| 724 | high | CWE-78 | function containing an execution sink is exposed as an RPC handler |
| 725 | high | CWE-693 | sandbox or global environment manipulated |
| 726 | medium | CWE-732 | self-modifying or destructive operation |
| 727 | medium | CWE-400 | unbounded string growth can exhaust memory |
| 728 | medium | CWE-1333 | untrusted data used as a search pattern |

## 7xx - payload and backdoor

| Code | Severity | CWE | Meaning |
| --- | --- | --- | --- |
| 741 | critical | CWE-94 | obfuscated code loader |
| 743 | critical | CWE-94 | decoded data fed to an execution sink |
| 745 | medium | CWE-693 | anti-analysis or watchdog behaviour |
| 746 | critical | CWE-506 | embedded machine-code blob |
| 747 | high | CWE-798 | hardcoded credential |
| 748 | critical | CWE-307 | scanner or credential brute-force loop |
| 749 | high | CWE-506 | persistence installed by the script |
| 750 | critical | CWE-1203 | matches a known exploit or malware signature |

### 747 notes

747 reports a secret written into the program, and it never puts the secret in
the finding: the finding carries the name the value was bound to, a `kind`, the
`length` of the value and a `redacted` form. A PEM block is redacted by its
header alone, because the header is the only part of a PEM that is not key
material, and the stars between the first and last two characters are capped at
eight, because the `length` field already carries the size.

**Two things have to agree before a value is reported: the name, and the value.**

*Name.* A name is **qualifying** when one of its words is a credential in its own
right - `password`, `passwd`, `pwd`, `passphrase`, `secret`, `token`,
`credential`, `psk`, `preshared`, `apikey`, `privkey` - or when the name with its
separators removed contains `apikey`, `privatekey` or `presharedkey`, which is
how `api_key`, `apiKey` and `x-api-key` qualify. A **bare** `key`, `auth`,
`pass`, `seed`, `licence` or `license` is weak evidence: in firmware these name
a table index or an 802.11 authentication mode as often as they name a
credential. A value under a bare name is reported only when the value itself
looks like a secret (below), and then at `low` confidence; a value under a
qualifying name is reported at `high`. Case is not part of a name:
`API_TOKEN`, `api_token` and `apiToken` are one name.

*Value.* The value has to be recognizably a secret rather than merely a string.
It is rejected when it is a path (`/etc/shadow`, `certs/ca.pem`, anything ending
in a key file suffix), a URL, a format string (`%s`, `$`, brackets, whitespace),
a number, an all-caps enum (`WEP`, `WPA2`, `EAP-TLS`), a placeholder
(`changeme`, `your-token-goes-here`), or a value every part of which is protocol
vocabulary - `EAP-TLS` is `eap` and `tls`, `wpa-psk` is `wpa` and `psk`, `ccmp` is
itself. Length is a floor, not a test: four characters under a qualifying name,
so that firmware's real defaults (`admin`, `root`, `toor`) are found, and twelve
under a bare name, because every protocol and mode token in the firmware corpora
is shorter than that while every credential in them is longer.

**A PEM header is not a key.** `-----BEGIN RSA PRIVATE KEY-----` is the first
line of a PEM, not a secret in it: a script that assembles a PEM at run time
holds the marker and computes the body, and a table of `-----BEGIN ...-----` and
`-----END ...-----` lines is exactly what a preamble looks like. A value whose
lines are all marker lines is never reported. A value that opens a block and
carries a base64 body is the key, and is reported whatever name it is filed
under, at `high`. When a file holds a marker and a body as separate literals,
the body is the finding.

**What 747 does not report.** A value the program only *compares* against - a
login check, a credential dictionary it tests input with - is the check, not a
leak; a credential read out of a configuration file has no literal to report; a
path to a CA bundle or a private key names a file rather than carrying one. A
table of default credentials *is* reported when the credential is a named field
with a shipped value, because that is the canonical CWE-798: the boundary is
between embedding a credential and checking one, not between two ways of
embedding it.

## 8xx - artifact and bytecode

| Code | Severity | CWE | Meaning |
| --- | --- | --- | --- |
| 801 | medium | - | Lua bytecode file, source cannot be analyzed |
| 802 | high | CWE-94 | bytecode references an execution sink |
| 803 | low | - | bytecode format does not match the assumed interpreter |
| 805 | low | - | file is not parseable Lua despite its name |

### 8xx notes

`luasec` does not decompile. A bytecode file always carries an 801: the source is
not available to analyze, and any statement about what the chunk does is a
statement about its data, not about its code.

- **801** fires for every file whose first bytes are `\27Lua` (5.1 to 5.4) or
  `\27LJ` (LuaJIT). A bytecode file never produces a 901.
- **802** fires when a string constant names an execution sink from the platform
  registry, either as a whole dotted path (`"os.execute"`) or as the two
  adjacent constants a compiled call leaves behind (`"os"` then `"execute"`).
  Adjacency is a heuristic, not a proven data flow, so the finding never claims
  `certain` confidence and the 801 alongside it is the honest summary.
- **803** fires when the chunk's flavor or version is not the interpreter we
  assume is running (5.4 by default; `analyze(paths, {assume_version = "5.1"})`
  overrides it). It also fires when the version byte names no release at all: the
  signature is still Lua's, but the file's only statement about its own encoding
  is one we cannot read, so the format demonstrably is not the one we assume.
  A *known* older version does not stop the constant table from being read: a 5.1
  chunk that names a sink is still a 802, because we have a reader for its
  layout. An *unknown* version does stop it, because there is no reader, and
  reporting a constant means claiming a layout the file never asserted.
- **805** fires when a file carries a bytecode signature but cannot be read as
  one: a truncated header, a failed `LUAC_DATA` / `LUAC_INT` / `LUAC_NUM`
  marker, or a prototype walk that stopped at one of its caps (100000 constants,
  64 levels of nesting, 100000 prototypes). Each is a property of the parser,
  not of the input, and the walk never allocates on a claimed length.

## 9xx - meta

| Code | Severity | CWE | Meaning |
| --- | --- | --- | --- |
| 901 | low | - | source could not be parsed, lexical scan only. Never filtered by `--severity-threshold`, and fails the run |
| 902 | low | - | source uses a Lua construct the parser does not support |
| 903 | low | - | API seen that is not available in the configured Lua standard |
| 904 | medium | - | analysis degraded for a large file; results are approximate. Never filtered by `--severity-threshold`, and fails the run |
