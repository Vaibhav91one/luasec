# Security policy

## Reporting a vulnerability in luasec

Open a private security advisory on the repository, or email the maintainer.
Please include a Lua sample that triggers the issue.

## Threat model for luasec itself

`luasec` reads untrusted, frequently malicious input: firmware Lua, precompiled
bytecode, and files with names chosen by an attacker. The tool is expected to
survive that input without hanging, exhausting memory, or executing anything it
analyzes. Specifically:

- The static analyzer never executes the Lua it reads.
- The payload validator (`--validate`) runs it in a separate process with `os` and
  `io` replaced by recorders, plus instruction, memory and wall-clock limits.
- Fixture generation is exempt, as authoring rather than analysis:
  `scripts/make-bytecode-fixtures.lua` shells out to `luac` (operands `%q` escaped)
  to write committed test bytes. It is not on the analysis path, and nothing
  `luasec` runs reaches it.
- Analysis is offline: no network access, no writes outside the requested output.
- Pattern matching is linear time; rules are checked against bounded input.

Report anything that violates the above.
