-- Interprocedural taint.
--
-- The common firmware shape is a wrapper: `local function run(cmd) os.execute(cmd) end`
-- called with a request parameter. luacheck's dataflow is intraprocedural, so we
-- bind formal parameters to actual arguments and propagate taint into the callee
-- until nothing changes.
--
-- Only functions defined in the analyzed file are in scope, and only when the
-- callee can be resolved from the call site. A wrapper whose argument never
-- carries untrusted data stays silent.
local platform_api = require "luasec.registry.platform_api"
local taint_engine = require "luasec.engine.taint"

local callgraph = {}

local MAX_ITERATIONS = 8
local MAX_DEPTH = 12

-- The Function node behind a call site's callee, when we can find it.
--
-- `globals` is the file's global function declarations, from globals_of. It is
-- consulted only for an Id that carries no `.var`, and that condition is the
-- whole justification for the lookup: an Id with no var is shadowed by no local
-- in scope, so a global declaration of that name in this file is what the
-- reference means. An Id that does carry a var is a local and returns before
-- reaching the table. Matching on the name alone instead would let a shadowing
-- local's call bind a same-named global's body, and invent a sink inside it.
local function resolve_callee(node, item, globals, depth)
   depth = depth or 0
   if depth > MAX_DEPTH or type(node) ~= "table" then return nil end

   if node.tag == "Invoke" then
      return resolve_callee(node[1], item, globals, depth + 1)
   end
   if node.tag == "Paren" then
      return resolve_callee(node[1], item, globals, depth + 1)
   end
   if node.tag == "Index" and node[2] and node[2].tag == "String" then
      return resolve_callee(node[1], item, globals, depth + 1)
   end
   if node.tag == "Call" then
      return nil
   end
   if node.tag == "Id" then
      if node.var then
         if item and item.used_values then
            for _, value in ipairs(item.used_values[node.var] or {}) do
               if value.node and value.node.tag == "Function" then
                  return value.node
               end
            end
         end
         return nil
      end
      -- No var, so this reference is a global. It resolves only if this file
      -- declares a global function of that name: a library function or a
      -- platform API has no body here, and inventing one would be a finding
      -- about a function nobody in this file wrote.
      return type(globals) == "table" and globals[node[1]] or nil
   end
   return nil
end

-- Global function declarations in the file, as name -> Function node.
--
-- luacheck's parser wraps `function f(x)` -- with no `local` -- in a Set whose
-- target is a bare Id and whose value is the Function node. `local function f`
-- is a Localrec instead and never reaches here, because resolve_locals gives it
-- a var and the used_values path already resolves it.
--
-- A Set whose target is an Index (`t.meth = function`) is not a global name and
-- is left out on purpose: resolve_callee reaches those through the receiver, and
-- keying them as "t.meth" would make a table field look like a global.
local function globals_of(chstate)
   local globals = {}

   for _, line in ipairs(chstate.lines) do
      for _, item in ipairs(line.items) do
         if item.tag == "Set" and item.node then
            local value = item.node[2] and item.node[2][1]
            local target = item.node[1] and item.node[1][1]
            if type(value) == "table" and value.tag == "Function"
                  and type(target) == "table" and target.tag == "Id"
                  and type(target[1]) == "string" then
               globals[target[1]] = value
            end
         end
      end
   end

   return globals
end

-- Argument nodes of a call expression.
local function args_of(node)
   local args = {}
   if node.tag == "Call" then
      for index = 2, #node do args[#args + 1] = node[index] end
   elseif node.tag == "Invoke" then
      -- `#index - 2` reads as the length of `index` minus two, because # binds
      -- tighter than -. On a number that raises, and it raised on every method
      -- call with at least one argument whose receiver resolved to a function
      -- through a local: one line of ordinary Lua, and the whole scan died with
      -- a traceback and no report at all.
      for index = 3, #node do args[index - 2] = node[index] end
   end
   return args
end

-- Formal parameters of a function node: {vars = {...}, varargs = bool}
local function formals_of(function_node)
   local args = function_node[1] or {}
   local varargs = false
   local vars = {}
   for index, arg in ipairs(args) do
      if arg.tag == "Dots" then
         varargs = true
      else
         vars[#vars + 1] = arg.var
      end
   end
   return vars, varargs
end

--- Every call site in the file, as {callee = Function node, args = nodes, item = item}.
--
-- A call is a site wherever it is *evaluated*, not only where it is the entire
-- statement. The rule used to be `item.tag == "Eval"` and the node being the
-- call, which made every call whose result is stored invisible:
--
--     local argv = parse_cmdline(...)        -- a Local item
--     result = execute(...)                   -- a Set item
--
-- On corpus/luci-1806/.../controller/commands.lua that hid 58 of the 91 call
-- nodes in the file. Those are the shapes LuCI is written in -- a handler is a
-- global function and its callers are nearly all assignments -- so both halves
-- of this had to move together. See the PR for the measurement.
--
-- `return f(x)` is deliberately not handled here: a Noop item's node is the
-- Return, and taint.lua already binds through that shape, so adding it would
-- bind the same call twice.
function callgraph.call_sites(chstate)
   local sites = {}
   local globals = globals_of(chstate)

   -- Nested calls are sites too: `ipairs(parse(x))` and `os.execute(run(x))`
   -- evaluate `parse` and `run` just as `local r = parse(x)` does, and a callee
   -- that only ever appears inside another call's arguments was never bound.
   -- A Function node is not entered: its body is its own line. Depth-capped so
   -- a pathological expression cannot recurse without bound.
   local function record(node, item, depth)
      depth = depth or 0
      if type(node) ~= "table" or depth > 64 or node.tag == "Function" then return end
      if node.tag == "Call" or node.tag == "Invoke" then
         local callee = resolve_callee(node[1], item, globals, 0)
         if callee then
            sites[#sites + 1] = {callee = callee, args = args_of(node), item = item}
         end
      end
      for _, child in ipairs(node) do
         if type(child) == "table" then record(child, item, depth + 1) end
      end
   end

   for _, line in ipairs(chstate.lines) do
      for _, item in ipairs(line.items) do
         if item.tag == "Eval" then
            record(item.node, item)
         elseif item.tag == "Local" or item.tag == "Set" then
            -- One value slot per name on the left, so `local a, b = f(), g()`
            -- is two calls and each is bound on its own.
            for _, value in ipairs(item.rhs or {}) do
               record(value, item)
            end
         end
      end
   end

   return sites
end

-- Lines indexed by the function they belong to. Building this once per file and
-- looking each function up turns the 708 pass from O(functions x lines) into
-- O(lines + functions): at 32,000 one-line functions the old shape took 19
-- minutes, and this is the same answer.
function callgraph.index_lines(chstate)
   if callgraph._index_for == chstate then return callgraph._index end
   local index = {}
   for _, line in ipairs(chstate.lines) do
      if line.node then
         local bucket = index[line.node]
         if not bucket then
            bucket = {}
            index[line.node] = bucket
         end
         bucket[#bucket + 1] = line
      end
   end
   callgraph._index_for, callgraph._index = chstate, index
   return index
end

--- Does this function contain an execution sink? Used by 708 and 724.
function callgraph.has_sink(chstate, function_node)
   for _, line in ipairs(callgraph.index_lines(chstate)[function_node] or {}) do
      for _, item in ipairs(line.items) do
         if item.tag == "Eval" then
            local node = item.node
            if node and (node.tag == "Call" or node.tag == "Invoke") then
               local path = taint_engine.callee_path(node[1], item, taint_engine.new_state())
               local sink = path and platform_api.match_sink(path) or nil
               local shape = path and platform_api.match_shape(path) or nil
               if sink or shape then
                  return true, path, sink and sink.code or (shape and shape.code), node
               end
            end
         end
      end
   end

   return false
end

--- Does this function contain an execution sink reachable from its parameters?
-- Taint the parameters, propagate, and see whether a sink fires.
function callgraph.sink_from_arguments(chstate, state, function_node, sink_holder)
   for _, line in ipairs(callgraph.index_lines(chstate)[function_node] or {}) do
      if line.node == function_node then
         for _, item in ipairs(line.items) do
            if item.tag == "Eval" then
               local node = item.node
               if node and (node.tag == "Call" or node.tag == "Invoke") then
                  local path = taint_engine.callee_path(node[1], item, state)
                  local sink = path and platform_api.match_sink(path) or nil
                  if sink and sink.arg and sink.arg[1] then
                     local arg = args_of(node)[sink.arg[1]]
                     -- Recorded whether or not it is tainted: the caller
                     -- decides whether an untraced argument is an exposure or a
                     -- constant.
                     if arg then
                        sink_holder[#sink_holder + 1] = {path = path, sink = sink, arg = arg,
                           item = item, node = node}
                     end
                  end
               end
            end
         end
      end
   end
end

return callgraph
