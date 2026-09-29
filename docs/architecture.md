# Architecture

`luasec` is two things: a static analyzer that finds untrusted data reaching
execution, and a set of detectors for malicious Lua that is already present.
Both work on the same parsed program.

## Layers

```
  input (file, directory, byte string)
    |
    v
  [1] artifact triage      bytecode sniff, raw lexical scan
    |
    v
  [2] front end            luacheck decoder + lexer + parser
    |                      Lua 5.1 / 5.2 / 5.3 / 5.4 / LuaJIT
    v
  [3] program model        luacheck linearize + resolve_locals
    |                      control flow graph, flow-sensitive reaching definitions
    v
  [4] knowledge            platform API registry (sources, sinks, propagators,
    |                      sanitizers) + firmware profiles
    v
  [5] engines              taint (intra + interprocedural), payload rules,
    |                      firmware rules, secret scanning
    v
  [6] findings             code, severity, confidence, CWE, source, trace
    |
    v
  [7] report               plain, JSON, SARIF (with codeFlows), HTML

  a single candidate payload, separately:

  source ──▶ [8] validator  child process, recorders for os/io, bounded
```

## Why luacheck is the base

Luacheck already solves the parts that are expensive to get right:

- a Lua parser that handles five dialects, with exact byte offsets for every node;
- a control flow graph where each expression is an item in a linearized line;
- `resolve_locals`, which connects every variable access to the assignments that
  can reach it, including through closures, loops and gotos.

Taint is then a small addition on top of a solved problem: attach a taint set to
each value object luacheck already created, and union sets as expressions are
evaluated. That is why `engine/taint.lua` is a few hundred lines rather than a
thousand, and why the tool is flow-sensitive without a hand-written CFG.

What luacheck has no concept of, and what we add: untrusted sources, dangerous
sinks, propagation rules, sanitizers, severity, confidence, CWE, and reports that
CI can consume.

## Data model

`luacheck.stages.linearize` turns the AST into `Line` objects. Each `Line` holds
`items` (an `Eval` per expression, plus `Local`/`Set`/`OpSet` for assignments and
`Jump`/`Cjump` for control flow) and, for a function, its arguments and body.
`resolve_locals` then fills `item.used_values[var]`, mapping each access to the
value objects that can reach it.

The taint engine stores `value -> taint set` in a weak-keyed table and iterates
every item until nothing changes. Taint only ever grows, so the iteration is
monotone and the cap on iterations makes termination a property rather than an
accident.

## Platform registry

Everything the analyzer knows about a platform's functions is data in
`registry/platform_api.lua` and the profiles in `registry/stds/`:

- **sources** - calls whose result is attacker-influenced (`http.formvalue`);
- **sinks** - calls that execute (`os.execute`) or evaluate (`loadstring`);
- **propagators** - calls that pass taint from argument to result;
- **sanitizers** - calls that neutralize taint, **per sink kind**, because a
  shell-quoting helper must not silence a dynamic-code finding.

Adding a platform is a data change. It is the difference between one rule engine
for OpenWrt, OpenResty, HiSilicon and ESP, and four.

## Precision

Three mechanisms keep the false-positive rate low enough to run on a whole
firmware tree:

1. **Constant folding** (`util/const_eval.lua`) proves when an argument is fixed
   at parse time, so `os.execute("ping -c1 " .. "127.0.0.1")` is silent.
2. **Confidence and severity** on every finding, with `--min-confidence` and
   `--severity-threshold` gates.
3. **Sink-specific sanitizers**, so recognizing a quoting helper does not
   silence an unrelated class of bug.

## The payload validator

The static pass answers "could this data reach execution". The validator answers
the complementary question: given a candidate payload, does running it actually
reach execution, and how far does it get before it is stopped.

It is the only part of luasec that executes anything, so it is built around one
rule: **the payload never runs in the analyzer's process.** `validate/driver.lua`
assembles `validate/child.lua`, the payload and the limits into a single
`lua -e` program, spawns it, and reads back a verdict. The parent only ever sees
records on a pipe.

```
  source ──▶ driver ──▶ [ lua -e child.lua + payload + limits ] ──▶ records ──▶ verdict
              │                    │
              │                    └── os, io are allowlists; package, debug, dofile,
              │                        loadfile, require, load(binary) are recorders;
              │                        string.rep/format and table.concat are size
              │                        checked, through the string metatable too
              │
              ├── wall clock watchdog (whole seconds), `ulimit -t`
              └── resident-set watchdog (samples the child, kills it past a
                  threshold): /proc/<pid>/statm on Linux, `ps -o rss=` elsewhere
```

What the payload is given is a fresh table with no metatable, so `_G` inside the
payload is that table and there is no `__index` fallback to the real globals. The
real `io`, `os`, `package` and `debug` are captured in locals before it runs, and
the payload only ever sees recorders that log the call, hand back something
harmless and let the payload carry on - so the rest of its behaviour stays
visible.

`os` and `io` are built by naming the members the payload may have rather than by
copying the real tables. That is load-bearing rather than tidier: a copy hands
over every member nobody thought about, and `io.stdout` is one of them, a live
handle on the record channel. The three standard streams the payload does get are
in-memory captures, and the record channel is the child's standard error with the
child's standard output on `/dev/null`, so a real stdout handle would be no use
either. Every record additionally carries a per-run nonce the parent generated and
only the child is given, so a line on the channel without it is dropped rather
than parsed.

Every bound inside the child is monotonic, which is what makes those
un-defeatable: a payload can catch the error a limit raises and keep going, but
the instruction counter, the memory reading and the load depth only ever climb,
so the next check still fires. The two watchers in the parent are not defeatable
at all, for a different reason: they are separate processes whose only inputs
are the child's pid and two constants the payload never sees.

- **instructions** - a `debug.sethook` count hook, checked every 100 instructions.
  Re-installed on every coroutine, because the hook belongs to a thread and a new
  thread starts with none.
- **memory, heap** - `collectgarbage("count")` on every tick, plus size checks in
  front of `string.rep`, `string.format` and `table.concat`, which are the
  standard functions that allocate far more than their arguments describe inside a
  single C call where no hook can see it coming. The `string` check is installed
  on the metatable every string carries as well as on the `string` table, because
  `("a"):rep(n)` never looks at the table. What this bounds is the live Lua heap,
  not the resident set, and it is a check between allocations rather than a
  limit: a payload that allocates inside one C call is not seen by it.
- **memory, resident set** - enforced by the parent, because the heap check
  cannot be and because nothing inside the child can preempt `..`. `OP_CONCAT` is
  one C-level call, so a loop doubling a string finishes inside a single tick:
  measured at 65.6x the ceiling before this watchdog existed. A second shell job
  beside the wall-clock watchdog samples the child - the second field of
  `/proc/<pid>/statm` on Linux, which is one `read` and no fork, and
  `ps -o rss= -p <pid>` elsewhere, which is one fork - and kills it past
  `rss_limit_kb` (default 1.5x the heap ceiling, above the 1.27x an honest
  payload reaches). `ulimit -v` is set too and is a real kernel bound on Linux;
  macOS refuses `RLIMIT_AS` and `RLIMIT_DATA` outright, which is why the
  watchdog exists rather than only the ulimit. The bound is the threshold plus one
  sampling window of allocation, and SECURITY.md has the measured peak for every
  reproducer.
- **source** - the payload the driver pastes in is size checked before the child
  program exists, and every chunk the payload compiles is size checked again in
  the child, so `load` of an assembled chunk is not a way around it. Every chunk
  is also screened for a self-concatenation, `x = x .. x`, which is the shape
  `..` takes when a payload uses it to double: a screen, not a bound, and
  SECURITY.md says which of the two the measured numbers belong to.
- **load depth** - every chunk the payload builds runs one level deeper.
- **wall clock** - enforced by the child on every tick and by the parent, which
  kills the child, with `ulimit -t` as a kernel backstop. The child cannot be
  trusted to notice time passing on its own, because a `while true do end` wedged
  in a C-level call would never reach a hook. The parent's watchdog sleeps a whole
  number of seconds, because the value reaches `sleep` as text and a fractional
  one is read by `sleep` as a rounding error.

The verdict vocabulary, in the order the runner decides it:

| Verdict | Meaning |
| --- | --- |
| `rce` | the payload reached an execution sink: `os.execute`, `io.popen`, `package.loadlib`, `dofile`, `loadfile`, `require`, or a precompiled chunk |
| `escape` | it tried to control the process it was running in, and executed nothing |
| `partial` | it reached a capability that is not execution: a file read or write, or the debugger |
| `timeout` | a bound stopped it: instructions, heap ceiling, resident set, wall clock or load depth |
| `benign` | it ran to completion and reached nothing |
| `error` | the payload or the sandbox itself failed, including a child running under a dialect the sandbox does not support |

Reaching a sink outranks being stopped: a payload that calls `os.execute` and then
loops forever is `rce`, with the limit in `exit_reason`, because the thing that
matters already happened. The ladder is ordered by how much each verdict
overstates - execution first, then process control, then a limit stop, then any
other reach - so that `os.exit`, which ends the process and runs nothing, is
`escape` and not `rce`. `escape` fails a build on the same exit code as the rest:
the snippet tried to leave the sandbox, and that is the finding.

The transport is length framed (`<bytes>:<the bytes>`, or a bare integer) so a
value containing spaces or newlines cannot be mistaken for a field boundary, and
what the payload printed is captured and reported as `payload_output` rather than
written to the record channel.

## What a verdict is not

A verdict is an outcome, not a finding, so it has no severity, no CWE and no
threshold to apply - but some of its fields are still text an attacker chose. What
the snippet printed (`payload_output`), what it returned (`payload_result`), the
argument it passed to a sink (`sinks_reached[].arg`) and its own error message
(`exit_reason`, when `reason_source` is `payload`) are all the payload's words.
The plain report labels them, escapes control bytes in them and prints them in a
`payload|` gutter; the JSON names them `payload_*` and carries a `note` saying
which fields they are. The chain, the sink names, the kinds, the line numbers and
the verdict itself are luasec's, and come from the sandbox rather than the payload.

## What is out of scope

- No execution of analyzed code in the static path. `--validate` is a separate,
  explicit mode that runs one snippet, in a child process, under the bounds above.
- No whole-program analysis by default: `--whole-program` resolves calls across
  files, which is slower and needs a real rootfs.
- Taint follows the return value of a local function and of a module field in
  the same file. A function that hands its argument back
  (`local function id(x) return x end`, or `function M.id(x) return x end`) is
  followed, so `os.execute(id(http.formvalue("h")))` is reported. Under
  `--whole-program`, the return value of a function in a module bound with
  `local m = require "mod"` is also followed (`m.id(x)`). A method call
  (`M:m`), a function passed as a value, and a `require(...)` called inline
  inside an expression are not followed: that flow stops and no finding is
  produced. Firmware that pipes request data through such a helper is missed,
  and that is a known limit rather than a clean bill of health.
- Bytecode is triaged, not decompiled.
