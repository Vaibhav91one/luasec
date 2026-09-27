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
- The child's **resident set** is bounded from outside the child, by a watcher the
  parent starts before the payload exists. Nothing inside the child can do it,
  because `..` is a single C-level call no Lua hook can preempt, and the measured
  numbers for that are in the next section.
- Analysis is offline: no network access, no writes outside the requested output.
  The validator writes no temporary files; the payload rides to the child inside
  the child's own command line.
- Pattern matching is linear time; rules are checked against bounded input.

## What the memory bound actually is, measured

There are two of them, they measure different things, and only one of them is a
bound.

**The child's heap ceiling is cooperative.** It is a ceiling on live Lua bytes,
read with `collectgarbage("count")` on every one of the 100-instruction ticks,
plus a size check in front of the three standard functions that can allocate far
more than their arguments describe - `string.rep`, `string.format`,
`table.concat`. It is cooperative because it can only be checked between
allocations, and it is a heap ceiling rather than a resident set ceiling because
that is all a Lua-level check can see. It costs, measured by running five million
instructions with and without the count hook: 16.0ms without, 24.6ms with, so
about 8.6ms of the budget. The `string` check is installed
on the metatable every string carries as well as on the `string` table, because
`("a"):rep(n)` never goes through the `string` table at all; the payload is given
`getmetatable` and can overwrite `__index.rep` to weaken the guard for its own
run, and cannot put the real `string.rep` back, because the real table is a local
upvalue and that metatable is the only route to it.

**The child's resident set is bounded from outside.** A cooperative check cannot
hold the line against an allocation that happens inside a single C call, and `..`
is exactly that: it compiles to `OP_CONCAT`, the instruction hook does not run
inside it, and a Lua count hook cannot preempt it. A loop that doubles a string
therefore does its whole work inside one tick window. Measured, against the
default 64MB ceiling, before this bound existed:

    local s = ("a"):rep(1024 * 1024)
    for i = 1, 20 do s = s .. s end
    return #s

    4297359360  maximum resident set size
    4297375744  maximum resident set size
    4297359360  maximum resident set size

65.6x the ceiling, and the verdict still read `timeout` with "memory ceiling of
65536kB exceeded", because the child's own check did fire - 4096 instructions
after the payload had already passed the ceiling by 64x. A verdict that reads as a
ceiling which held is worse than one that admits it did not.

So the parent starts a second watcher beside the wall-clock watchdog, in the same
shell group, with the same shape: one child, two independent kill reasons, both
watchers killed before the group exits so neither outlives the record pipe and
hangs the caller. It samples the child's resident set and kills it past a
threshold:

- **Linux**: the second field of `/proc/<pid>/statm`, read by the shell's own
  `read`. One file open and no fork per sample, so the sampling gap is the sleep
  and nothing else.
- **Everywhere else**: `ps -o rss= -p <pid>`. One fork, measured at 2.93ms per
  sample on this machine. That cost is the floor of what is measurable from a
  shell without a C binding, and it is what sets the overshoot on macOS.
- `ulimit -v` is still set, and on Linux it is a real kernel bound
  (`RLIMIT_AS`). On macOS it is refused outright, which is why it cannot be the
  bound here:

      $ /bin/sh -c 'ulimit -v 204800'
      /bin/sh: line 0: ulimit: virtual memory: cannot modify limit: Invalid argument
      $ /bin/sh -c 'ulimit -d 204800'
      /bin/sh: line 0: ulimit: data seg size: cannot modify limit: Invalid argument

  `ulimit -t` does work on macOS (measured: the child dies of SIGXCPU, exit
  status 152), which is why the CPU side has a kernel backstop and the memory side
  has a watcher.

The payload cannot influence the watcher. Its whole text is generated from
constants, the only variable it reads is the pid the shell took from `$!` before
the payload existed, and its one line to the parent goes out on the record pipe
gated by the same per-run nonce as the child's records.

### The achievable bound, and the two knobs

    rss_limit_kb   the threshold, in kB. Default: 1.5 x max_memory_kb (98304 kB
                   at the default ceiling). Also settable as rss_multiplier.
    rss_poll_ms    the sampling gap while the child is small. Default: 1.
                   Also settable as rss_limit_kb's companion; 0 means no sleep.

The default multiplier is 1.5 because the threshold has to sit above what an
honest payload reaches, and that is measured at 1.27x (81.50MB, the
`table.concat` row below). Below 1.27x the watcher would report a memory
exhaustion the payload never caused, and a spec pins that it does not.

Once the child is within half the limit the watcher stops sleeping, because the
sleep is on top of the sample cost and the overshoot is decided in that window.
The spin is paid only by payloads already holding memory, and a payload that
completes in 5ms is sampled twice.

**The bound is not the threshold.** It is the threshold plus whatever the child
can allocate between two samples, and the achievable statement is exactly that:

> peak resident set <= the threshold, plus one sampling window of allocation

At the default 1ms gap on macOS that window is 2.93ms of `ps` plus 1ms of sleep,
and at the 32GB/s concatenation throughput measured on this machine that is about
125MB. So the default settings land at roughly 2x the heap ceiling, and the
poll interval is what moves it. The same payload, through
`luasec.api.validate_payload` with `rss_poll_ms` set, worst of five each:

| `rss_poll_ms` | worst peak RSS | x the 64MB ceiling |
| --- | --- | --- |
| 1 (default) | 123.97MB | 1.94x |
| 5 | 139.75MB | 2.18x |
| 20 | 467.14MB | 7.30x |
| 100 | 1624.03MB | 25.38x |

The last row is the point of stating the bound in those terms rather than as a
number: the window is the bound, and a 100ms window is a 1.6GB window. It is
still bounded - the wall clock and the child's own heap ceiling both still hold -
but it is 25x the ceiling rather than 2x, which is why 1ms is the default and why
it is not a knob to turn casually. On Linux the same table is much flatter,
because there a sample is a `read` of `/proc/<pid>/statm` rather than a fork, and
`ulimit -v` is a kernel bound underneath it.

### Peak resident set, measured

macOS 26.5 / arm64, `/usr/bin/time -l` around the whole run, 5 runs each,
default 64MB ceiling and default 98304kB threshold. `max` is the worst of the
five; the last column is that worst case against the 64MB ceiling.

| Payload | Verdict | max peak RSS | x ceiling |
| --- | --- | --- | --- |
| benign snippet | `benign` | 3.11MB | 0.05x |
| `("a"):rep(500 * 1024 * 1024)` | `timeout`, refused before allocating | 3.09MB | 0.05x |
| 4000 x `("x"):rep(1024 * 1024)` | `timeout`, refused in front of the allocation | 67.22MB | 1.05x |
| 60000 x 1KB parts then `table.concat` | `timeout`, refused in front of the concat | 81.50MB | 1.27x |
| `while true do io.open(...) end` | `timeout`, 34376 sink records | 35.39MB | 0.55x |
| the doubling payload, `s = s .. s` | `timeout`, refused before compiling | 3.12MB | 0.05x |
| the same loop as a table field, so the screen cannot see it | `timeout`, killed by the parent | 140.14MB | 2.19x |

Two things that table does not hide:

- The 81.50MB row is a live set of about 60MB that `table.concat` would have
  doubled. The check in front of it refuses that, so the remainder is allocator
  overhead rather than an allocation the ceiling missed. This is the 1.27x the
  default 1.5x multiplier is set above.
- A payload that reaches a sink in a loop produces one record per call, and the
  parent reads them all. That is bounded by the instruction budget: 34376 records
  and 35.39MB of peak RSS for the flood above.

### The screen, which is not a bound

The last two rows are different in kind and the difference is not a matter of
wording. The child screens the *source shape* of the doubling loop - a bare name
on both sides of a `..` - and refuses to compile such a chunk, in front of every
chunk it compiles and not only the one the driver pasted in. That is why the
second-to-last row is 3.12MB: the payload never ran.

It is a screen, not a bound. One character defeats it. `s = s .. (s)` is not
caught, `s[1] = s[1] .. s[1]` is not caught, and the last row is that second form
measured, at 140.14MB - stopped by the watcher, not by the screen. Anything
assembled at run time meets the screen only because the screen happens to be in
front of every chunk. The pattern is narrow because the cost of a screen is a
false positive: `out = out .. piece`, which is how firmware builds a response, is
untouched.

So: **the honest statement is that the child's heap ceiling is cooperative, the
child's resident set is bounded from outside at roughly 2x the heap ceiling, and
the source screen in front of `..` removes the obvious reproducer but bounds
nothing.** Before this work the tool's peak for that payload was 65.6x the
ceiling and it said "memory ceiling exceeded"; it is now 0.05x for the payload as
written and 2.19x for the same loop with one character changed, and it says which
of the two happened.

## What else is worth stating plainly

The parent's watchers need `sleep` and a POSIX shell, the same external tools
`cli/walk.lua` already relies on. The wall-clock watchdog's `sleep` is given a
whole number of seconds, rounded up, because the value is passed as text: a
fractional second formats as something like `1e-07`, which `sleep` reads as a
rounding error and returns immediately, leaving the payload with no wall clock at
all. The resident-set watcher is different - its sleep is a sampling interval, not
a deadline, so it is fractional, and it is written as a fixed-point literal so it
can never come out as `1e-07`. If a `sleep` on some platform refuses a fraction,
the watcher says so on the record channel and the verdict's `exit_reason` says the
resident-set bound could not be installed, rather than leaving a bound silently
absent. Without either tool the child is still bounded by its own limits and by
`ulimit -t`, but a child wedged in a C-level loop would not be killed on time, and
nothing would stop the doubling chain in `..` but the child's own tick.

A child the watcher kills and a child the wall clock kills both end in SIGKILL,
so both leave the same exit status behind. The reason is in the verdict's
`exit_reason`, and the two are distinguishable there - "resident set of NNNNkB
exceeded the MMMMkB limit" against "wall clock of Nms exceeded" - which is the
point: an operator should not have to guess which bound fired.

`os.exit` is reported as a process-control escape and not as an execution. Ending
the process runs nothing, and a verdict that says a snippet achieved code
execution when it only asked to be terminated is over-strong in the one field an
operator is most likely to act on. It stays in the escapes list with its line
number, and a payload that reaches a sink that runs something *and* then calls
`os.exit` is still `rce`, because the thing that matters already happened.

Every field of a verdict that the payload chose - what it printed, what it
returned, the argument it passed to a sink, and its own error message - is
labelled as payload text in the plain report, prefixed `payload|`, and named
`payload_*` in the JSON, with a note in the JSON saying so. Control bytes are
escaped, so a payload cannot put a newline or a carriage return into a line the
report is counting. This is about not putting words in someone's log. It is not a
claim that the payload cannot influence what the tool prints: a payload can
choose its own output, and the tool shows it, in a gutter, as data.

Report anything that violates the above.
