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
              │                    └── os, io, package, debug, dofile, loadfile,
              │                        require, load(binary) are recorders;
              │                        string.rep/format are size checked
              │
              └── wall clock watchdog, `ulimit -t`, `ulimit -v`
```

What the payload is given is a fresh table with no metatable, so `_G` inside the
payload is that table and there is no `__index` fallback to the real globals. The
real `io`, `os`, `package` and `debug` are captured in locals before it runs, and
the payload only ever sees recorders that log the call, hand back something
harmless and let the payload carry on - so the rest of its behaviour stays
visible.

Every bound is monotonic, which is what makes them un-defeatable: a payload can
catch the error a limit raises and keep going, but the instruction counter, the
memory reading and the load depth only ever climb, so the next check still fires.

- **instructions** - a `debug.sethook` count hook, checked every 100 instructions.
  Re-installed on every coroutine, because the hook belongs to a thread and a new
  thread starts with none.
- **memory** - `collectgarbage("count")` in the same hook, plus size checks in
  front of `string.rep` and `string.format`, which are the two standard functions
  that turn a small argument into a huge allocation inside one C call where no
  hook can see it coming. `ulimit -v` is a backstop where the platform enforces it.
- **load depth** - every chunk the payload builds runs one level deeper.
- **wall clock** - enforced by the parent, which kills the child, with `ulimit -t`
  as a backstop. The child cannot be trusted to notice time passing, because a
  `while true do end` in a C-level loop would never reach a hook.

The verdict vocabulary, in the order the runner decides it:

| Verdict | Meaning |
| --- | --- |
| `rce` | the payload reached an execution sink: `os.execute`, `io.popen`, `package.loadlib`, `os.exit`, `dofile`, `loadfile`, `require`, or a precompiled chunk |
| `partial` | it reached a capability that is not execution: a file read or write, or the debugger |
| `timeout` | a bound stopped it: instructions, memory, wall clock or load depth |
| `benign` | it ran to completion and reached nothing |
| `error` | the payload or the sandbox itself failed |

Reaching a sink outranks being stopped: a payload that calls `os.execute` and then
loops forever is `rce`, with the limit in `exit_reason`, because the thing that
matters already happened.

The transport is length framed (`<bytes>:<the bytes>`, or a bare integer) so a
value containing spaces or newlines cannot be mistaken for a field boundary, and
what the payload printed is captured and reported as `output` rather than written
to the report channel - a payload that could write there could forge a verdict.

## What is out of scope

- No execution of analyzed code in the static path. `--validate` is a separate,
  explicit mode that runs one snippet, in a child process, under the bounds above.
- No whole-program analysis by default: `--whole-program` resolves calls across
  files, which is slower and needs a real rootfs.
- Bytecode is triaged, not decompiled.
