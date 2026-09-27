# Rule catalogue

Every finding carries a stable three-digit code, a severity, a confidence and,
where one applies, a CWE reference. Codes in the 0xx-6xx range belong to
[luacheck](https://github.com/lunarmodules/luacheck) and are never reused here.

Severity: `critical`, `high`, `medium`, `low`.
Confidence: `certain` (the data flow is unambiguous), `high`, `medium` (heuristic
default), `low` (shape only, no proven flow).

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
| 708 | medium | CWE-78 | execution sink reached only through a wrapper |
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
| 742 | high | CWE-94 | precompiled code dump used to reconstitute a function |
| 743 | critical | CWE-94 | decoded data fed to an execution sink |
| 744 | high | CWE-94 | dynamic evaluation wrapped in error suppression |
| 745 | medium | CWE-693 | anti-analysis or watchdog behaviour |
| 746 | critical | CWE-506 | embedded machine-code blob |
| 747 | high | CWE-798 | hardcoded credential |
| 748 | critical | CWE-307 | scanner or credential brute-force loop |
| 749 | high | CWE-506 | persistence installed by the script |
| 750 | critical | CWE-1203 | matches a known exploit or malware signature |

## 8xx - artifact and bytecode

| Code | Severity | CWE | Meaning |
| --- | --- | --- | --- |
| 801 | medium | - | Lua bytecode file, source cannot be analyzed |
| 802 | high | CWE-94 | bytecode references an execution sink |
| 803 | low | - | bytecode format does not match the assumed interpreter |
| 804 | medium | - | highly obfuscated source |
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
  overrides it). It does not stop the constant table from being read: a 5.1
  chunk that names a sink is still a 802.
- **805** fires when a file carries a bytecode signature but cannot be read as
  one: a truncated header, a failed `LUAC_DATA` / `LUAC_INT` / `LUAC_NUM`
  marker, or a prototype walk that stopped at one of its caps (100000 constants,
  64 levels of nesting, 100000 prototypes). Each is a property of the parser,
  not of the input, and the walk never allocates on a claimed length.

## 9xx - meta

| Code | Severity | CWE | Meaning |
| --- | --- | --- | --- |
| 901 | low | - | source could not be parsed, lexical scan only |
| 902 | low | - | source uses a Lua construct the parser does not support |
| 903 | low | - | API seen that is not available in the configured Lua standard |
