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
local function resolve_callee(node, item, state, depth)
   depth = depth or 0
   if depth > MAX_DEPTH or type(node) ~= "table" then return nil end

   if node.tag == "Invoke" then
      return resolve_callee(node[1], item, state, depth + 1)
   end
   if node.tag == "Paren" then
      return resolve_callee(node[1], item, state, depth + 1)
   end
   if node.tag == "Index" and node[2] and node[2].tag == "String" then
      return resolve_callee(node[1], item, state, depth + 1)
   end
   if node.tag == "Call" then
      return nil
   end
   if node.tag == "Id" and node.var and item and item.used_values then
      for _, value in ipairs(item.used_values[node.var] or {}) do
         if value.node and value.node.tag == "Function" then
            return value.node
         end
      end
   end
   return nil
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
function callgraph.call_sites(chstate)
   local sites = {}

   for _, line in ipairs(chstate.lines) do
      for _, item in ipairs(line.items) do
         if item.tag == "Eval" then
            local node = item.node
            if node and (node.tag == "Call" or node.tag == "Invoke") then
               local callee = resolve_callee(node[1], item, nil, 0)
               if callee then
                  sites[#sites + 1] = {callee = callee, args = args_of(node), item = item}
               end
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
