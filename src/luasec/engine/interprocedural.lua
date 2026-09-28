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
local function bind_call(state, chstate, site)
   local function_node = site.callee
   if not taint_engine.line_of_function(chstate, function_node) then return false end

   local vars, varargs = taint_engine.formals_of(function_node)
   local arguments = site.args
   local bound = false

   for index, var in ipairs(vars) do
      local arg = arguments[index]
      if not arg then break end
      local arg_taint = taint_engine.of_expr(state, arg, site.item)
      if next(arg_taint) ~= nil then
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

   -- Functions this file calls are not exposures: whatever feeds them is here,
   -- and if it is untrusted the flow is already reported as 709.
   local called = {}
   for _, site in ipairs(callgraph.call_sites(chstate)) do
      called[site.callee] = true
   end

   for _, line in ipairs(chstate.lines) do
      local function_node = line.node
      if function_node and function_node.tag == "Function" and function_node.name then
         local has_sink = not called[function_node] and callgraph.has_sink(chstate, function_node)
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
