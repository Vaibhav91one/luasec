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

## What is out of scope

- No execution of analyzed code in the static path.
- No whole-program analysis by default: `--whole-program` resolves calls across
  files, which is slower and needs a whole rootfs.
- Bytecode is triaged, not decompiled.
