-- Interprocedural taint.
--
-- The dominant shape in firmware Lua is a wrapper: a function whose parameter is
-- passed straight to `os.execute`, called with a request parameter. Luacheck's
-- dataflow stops at the function boundary, so this pass binds formal parameters
-- to actual arguments and re-propagates until nothing changes.
--
-- It is deliberately conservative: only functions defined in the same file, only
-- callees resolvable from the call site, a bounded iteration count, and a
-- visited set so a cycle cannot loop.
local callgraph = require "luasec.engine.callgraph"
local codes = require "luasec.rules.codes"
local platform_api = require "luasec.registry.platform_api"
local taint_engine = require "luasec.engine.taint"

local interprocedural = {}

local MAX_ITERATIONS = 8

-- Mark a call site's arguments as tainted in the callee's parameter values.
--
-- A callee's vararg is a formal like any other, and binding to it is what makes
-- a forward reach: `function action_run(...) execute_command(cb, ...) end` hands
-- the dispatcher's URL path to `execute_command`, and nothing downstream of that
-- was tainted while the binding stopped at the positional formals a
-- `function(...)` does not have.
--
-- The confidence of a descriptor is unchanged by the hop, and that is the whole
-- decision rather than a default. Two things make it safe to say so:
--
--   * The binding is demand-driven. What lands here is written to
--     `param_taint[callee vararg]`, which `taint_of_expr` consults only when the
--     callee's body actually evaluates a `...`. A callee that discards the value
--     binds nothing that is ever read, so no claim is made on its behalf --
--     `function g(a, ...) return a end` called as `g(clean, tainted)` leaves `a`
--     clean, and that is specified rather than assumed.
--   * The confidence describes the *source*, not the path. `high` says the data
--     is what `http.formvalue` returned; `medium` says it is what a profile
--     declares a dispatcher argument to be. A forward does not change what the
--     data is, only where it is read. Every discount this codebase applies
--     (`filter_split`, `check_validator`) is for evidence that the value was
--     *neutralised on the way to the sink*, and forwarding is not that.
--
-- What a hop does cost is index precision: the callee chooses which element of
-- its vararg to read, and it may choose one the caller cannot reach, so
-- `select(1, ...)` after `run("/usr/bin/true", untrusted)` is a claim this model
-- cannot make exact. That imprecision belongs to the *vararg*, not to the
-- forwarding -- #226 accepts it unpaid for `{...}` inside the handler itself --
-- so charging for it again per hop would price a path length instead of a piece
-- of missing evidence, and would report a three-hop firmware dispatcher below a
-- one-hop one for no difference in what is known.
local function bind_call(state, chstate, site)
   local function_node = site.callee
   if not taint_engine.line_of_function(chstate, function_node) then return false end

   local vars, varargs = taint_engine.formals_of(function_node)
   local arguments = site.args
   local bound = false

   -- Fold an argument's taint into one formal, at most once per descriptor. A
   -- descriptor already there is not news, which is what keeps a function that
   -- forwards the same vararg to two callees from reporting one finding twice.
   local function bind_into(var, arg)
      local arg_taint = taint_engine.of_expr(state, arg, site.item)
      if next(arg_taint) == nil then return end
      local existing = state.param_taint[var]
      if not existing then
         existing = {}
         state.param_taint[var] = existing
      end
      for _, descriptor in pairs(arg_taint) do
         if not existing[descriptor.id] then
            existing[descriptor.id] = descriptor
            bound = true
         end
      end
   end

   for index, var in ipairs(vars) do
      local arg = arguments[index]
      if not arg then break end
      bind_into(var, arg)
   end

   -- Everything the callee takes beyond its last positional formal is its
   -- vararg, in one bag. A `...` *anywhere* in the call is in that bag too: in
   -- Lua the forwarded values fill the remaining positional formals and then run
   -- on into `...`, so `sink_fn("a", "b", ...)` reaches `sink_fn`'s vararg even
   -- though the `...` sits at a position the callee names. Whether it really
   -- does depends on how many values the caller's vararg holds, which is not
   -- knowable here -- the same over-approximation every positional binding makes.
   --
   -- `formals_of` hands back `true` rather than a var when resolve_locals gave
   -- the signature no var object; there is nothing to bind to in that case and
   -- writing to `param_taint[true]` would be a second, unrelated key.
   if type(varargs) == "table" then
      -- `f(..., ...)` hands the same node over twice. bind_into is idempotent,
      -- so the second fold is a no-op rather than a second finding, and the
      -- alternative -- a seen-set allocated per call site on every one of the
      -- eight iterations -- buys nothing this does not already have.
      for index = 1, #arguments do
         local arg = arguments[index]
         if index > #vars or arg.tag == "Dots" then
            bind_into(varargs, arg)
         end
      end
   end

   return bound
end

--- Run the pass. Returns the extra findings it produced.
function interprocedural.run(chstate, state, opts)
   opts = opts or {}
   local findings = {}
   local sites = callgraph.call_sites(chstate)

   if #sites == 0 then return findings end

   for _ = 1, MAX_ITERATIONS do
      local changed = false
      for _, site in ipairs(sites) do
         if bind_call(state, chstate, site) then changed = true end
      end

      -- Re-propagate so newly bound parameters reach sinks inside the callee,
      -- which is what makes a second wrapper level work.
      taint_engine.run(chstate, opts, state)

      if not changed then break end
   end

   for _, finding in ipairs(state.findings) do
      findings[#findings + 1] = finding
   end

   return findings, state
end

--- A function that contains an execution sink and is reachable from outside the
-- file: the sink exists, the input is somewhere we cannot see. That is 708.
function interprocedural.exposed_sinks(chstate, opts)
   opts = opts or {}
   local state = taint_engine.new_state()
   local exposed = {}

   -- How much evidence an in-file call supplies depends on whether another file
   -- can reach the function at all, so that is what decides it.
   --
   -- For a function nothing outside this file can reach, a resolved call is the
   -- only feed there is, and a call with a literal in it genuinely means the
   -- sink is fed a constant. The old rule -- any resolved call stands down --
   -- was right for those and is kept.
   --
   -- For an *assigned* function the opposite holds. Its real callers are in
   -- another file, because LuCI registers a handler by name and dispatches to it
   -- from the dispatcher:
   --
   --     function handler(cmd) os.execute(cmd) end   -- exported: entry({...}, handler)
   --     function boot() handler("cleanup") end       -- in-file, a literal
   --
   -- Counting that call as "fed" withdrew the 708 and added no 709, because
   -- "cleanup" is a constant: silence on an attacker-reachable sink, from a line
   -- that looks like it reduces noise. So an assigned function stands down only
   -- for a call that passes an argument this file cannot fold to a constant --
   -- the same `is_constant` test the rule applies below when it decides whether
   -- a sink argument is genuinely unaccounted for.
   --
   -- "Assigned" rather than "global", on purpose. luacheck's parser emits a Set
   -- for `function f()` and for `function t.f()` alike, and both can be reached
   -- from elsewhere, the second through the table it is written into -- which is
   -- how a LuCI controller exposes its handlers. It is also why this cannot be
   -- phrased as "global": `local function run` followed by `return run` is a
   -- Localrec that is handed straight out of the chunk, and 708 is right about
   -- that one.
   local assigned = {}
   for _, each in ipairs(chstate.lines) do
      for _, item in ipairs(each.items) do
         if item.tag == "Set" and item.node and item.node[2] then
            local value = item.node[2][1]
            if type(value) == "table" and value.tag == "Function" then
               assigned[value] = true
            end
         end
      end
   end

   local fed = {}
   for _, site in ipairs(callgraph.call_sites(chstate)) do
      if not assigned[site.callee] then
         fed[site.callee] = true
      else
         for _, arg in ipairs(site.args) do
            if not taint_engine.is_constant(arg) then
               fed[site.callee] = true
               break
            end
         end
      end
   end

   for _, line in ipairs(chstate.lines) do
      local function_node = line.node
      if function_node and function_node.tag == "Function" and function_node.name then
         local has_sink = not fed[function_node] and callgraph.has_sink(chstate, function_node)
         if has_sink then
            local reached = {}
            callgraph.sink_from_arguments(chstate, state, function_node, reached)
            for _, hit in ipairs(reached) do
               -- Three cases, and only the third is an exposure: tainted input
               -- already proven (reported as 709), an argument that is fixed at
               -- parse time (not a risk at all), and an argument we cannot trace
               -- to anything (the sink exists, its input lives in another file).
               if next(taint_engine.of_expr(state, hit.arg, hit.item)) == nil
                     and not taint_engine.is_constant(hit.arg) then
                  exposed[#exposed + 1] = {
                     function_node = function_node,
                     path = hit.path,
                     code = hit.sink.code,
                     name = function_node.name,
                     sink_line = hit.node and hit.node.line,
                     sink_offset = hit.node and hit.node.offset,
                  }
               end
            end
         end
      end
   end

   return exposed
end

return interprocedural
