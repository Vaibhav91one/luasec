# Security policy

## Reporting a vulnerability in luasec

Open a private security advisory on the repository, or email the maintainer.
Please include a Lua sample that triggers the issue.

## Threat model for luasec itself

`luasec` reads untrusted, frequently malicious input: firmware Lua, precompiled
bytecode, files with names chosen by an attacker, and - with `--validate` - Lua
that is about to be executed. The tool is expected to survive that input without
hanging, exhausting memory, or executing anything it analyzes. Specifically:

- The static analyzer never executes the Lua it reads.
- Fixture generation is exempt, as authoring rather than analysis:
  `scripts/make-bytecode-fixtures.lua` shells out to `luac` (operands `%q` escaped)
  to write committed test bytes. It is not on the analysis path, and nothing
  `luasec` runs reaches it.
- The payload validator (`--validate`) never executes the payload in the analyzer's
  own process either. It runs in a child interpreter, so a bug in the validator
  costs one child process and not the analysis.
- In that child, `os` and `io` are built from an allowlist of member names and
  `package`, `debug`, `dofile`, `loadfile` and `require` are emptied or recorded.
  An allowlist, not a copy of the real library: a copy hands over every member
  nobody thought about, and `io.stdout` is one of them. There is no filesystem,
  process or network capability left for the payload to reach, and a precompiled
  chunk is refused because Lua ignores the environment argument for one.
- The payload's three standard streams are in-memory captures, not handles.
  `io.stdout:write`, `io.stderr:write`, `print` and `warn` all land in the same
  capture, which the report labels as payload text.
- The record channel is the child's standard error. The child's standard output
  is `/dev/null`, so even a real handle on stdout could not put a byte in the
  channel the parent parses, and every record carries a per-run nonce the parent
  generated and only the child is given, so a line that reaches the channel
  without it is dropped. A payload cannot read the nonce: it has no `debug`, no
  upvalue access, no `os.getenv`, and no way to read the program text it was
  pasted into.
- The child is bounded by an instruction count, a memory ceiling, a load depth and
  a wall clock. The counters only climb, so catching a limit's error does not buy
  a payload anything. The wall clock is enforced twice: the child reads the clock
  every 100 instructions, and the parent kills the child, with `ulimit -t` as a
  kernel backstop.
- Analysis is offline: no network access, no writes outside the requested output.
  The validator writes no temporary files; the payload rides to the child inside
  the child's own command line.
- Pattern matching is linear time; rules are checked against bounded input.

Two things are worth stating plainly. The parent's wall clock needs `sleep` and a
POSIX shell, the same external tools `cli/walk.lua` already relies on; without
them the child is still bounded by its own limits and by `ulimit -t`, but a child
wedged in a C-level loop would not be killed on time. And `ulimit -v` is not
enforced on every platform, which is why the memory ceiling also lives in the
child's own instruction hook and in front of `string.rep` and `string.format`.

Report anything that violates the above.
