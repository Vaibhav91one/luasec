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

## What the memory ceiling is, measured

The memory ceiling is **cooperative, and it is a live Lua heap ceiling rather than
a resident set ceiling**. That is not a preference; on macOS it is forced:

    $ /bin/sh -c 'ulimit -v 204800'
    /bin/sh: line 0: ulimit: virtual memory: cannot modify limit: Invalid argument
    $ /bin/sh -c 'ulimit -d 204800'
    /bin/sh: line 0: ulimit: data seg size: cannot modify limit: Invalid argument

macOS refuses `RLIMIT_AS` and `RLIMIT_DATA` outright, so there is no
kernel-enforced memory limit available to the parent here. `RLIMIT_CPU` does work
(`ulimit -t 1` kills the child with SIGXCPU, exit status 152), which is why the CPU
side has a kernel backstop and the memory side does not. `ulimit -v` is still set
on platforms that honour it, and is a backstop there, not the bound.

What the child does enforce, and what that costs:

- `collectgarbage("count")` is read on every one of the 100-instruction ticks,
  not every sixty-fourth. The window between two checks is the entire budget a
  payload has to allocate past the ceiling, and 6400 instructions of
  `t[i] = ("x"):rep(1024 * 1024)` is about 4GB of it. The overhead is measured:
  a full five million instruction budget goes from 12ms to 25ms of CPU.
- The three standard functions that can allocate far more than their arguments
  describe are size-checked before they run: `string.rep`, `string.format` and
  `table.concat`.
- The `string` guard is installed on the metatable every string carries, as well
  as on the `string` table the payload is given. `("a"):rep(n)` does not go
  through the `string` table at all, so guarding only the table left one
  character of syntax between a payload and a 500MB allocation. The payload is
  given `getmetatable`, so it can read that metatable and can overwrite
  `__index.rep` to weaken the guard for its own run; it cannot put the real
  `string.rep` back, because the real table is a local upvalue and that metatable
  is the only route to it.

Peak resident set, measured on macOS 26.5 / arm64 with `/usr/bin/time -l` around
the whole run, against the default 64MB ceiling:

| Payload | Verdict | Peak RSS |
| --- | --- | --- |
| benign snippet | `benign` | 3.1MB |
| `("a"):rep(500 * 1024 * 1024)` | `timeout`, refused before allocating | 3.0MB |
| 4000 x `("x"):rep(1024 * 1024)`, i.e. the 4GB reproducer | `timeout` | 70.5MB |
| 60000 x 1KB parts then `table.concat` | `timeout` | 85.4MB |
| `while true do io.open(...) end` | `timeout`, 34376 sink records | 36.1MB |

Two things that number does not hide:

- The 85.4MB case is a live set of about 60MB that `table.concat` would have
  doubled. The check in front of it refuses that, so the remainder is allocator
  overhead rather than an allocation the ceiling missed. The practical bound is
  therefore "the ceiling, plus allocator overhead, plus whatever one tick of
  ordinary allocation adds" - measured here as up to about 1.3x the ceiling, not
  1x.
- A payload that reaches a sink in a loop produces one record per call, and the
  parent reads them all. That is bounded by the instruction budget: 34376 records
  and 36MB of peak RSS for the flood above.

## What else is worth stating plainly

The parent's wall clock needs `sleep` and a POSIX shell, the same external tools
`cli/walk.lua` already relies on. Its `sleep` is given a whole number of seconds,
rounded up, because the value is passed as text: a fractional second formats as
something like `1e-07`, which `sleep` reads as a rounding error and returns
immediately, leaving the payload with no wall clock at all. Without `sleep` the
child is still bounded by its own limits and by `ulimit -t`, but a child wedged in
a C-level loop would not be killed on time.

Every field of a verdict that the payload chose - what it printed, what it
returned, the argument it passed to a sink, and its own error message - is
labelled as payload text in the plain report, prefixed `payload|`, and named
`payload_*` in the JSON, with a note in the JSON saying so. Control bytes are
escaped, so a payload cannot put a newline or a carriage return into a line the
report is counting. This is about not putting words in someone's log. It is not a
claim that the payload cannot influence what the tool prints: a payload can
choose its own output, and the tool shows it, in a gutter, as data.

Report anything that violates the above.
