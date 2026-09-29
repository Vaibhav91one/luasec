-- Taint engine.
--
-- Taint is attached to luacheck *values* (the objects `resolve_locals` links an
-- access to its reaching assignment), so propagation is flow-sensitive for free:
-- `local a = x; x = "safe"; use(a)` sees a's own definition, not the later one.
--
-- Sources introduce taint at a call site. Propagation moves it through
-- concatenation, assignments, table fields, string/table library calls and
-- the return value of a function the analyzer can identify in the same file:
-- a local function, and a module field (M.id) in that same file. Under
-- --whole-program a required module's function return is followed too. What is
-- not followed: a method call (M:m), a function passed as a value, and
-- anything past the depth cap. Sinks consume taint and produce findings.
local platform_api = require "luasec.registry.platform_api"
local codes = require "luasec.rules.codes"
local const_eval = require "luasec.util.const_eval"

local taint = {}

local MAX_ITERATIONS = 20

-- Characters that change the meaning of a shell command when they reach it
-- unquoted. Reported by 712 so an operator can see the class of the bug.
local SHELL_METACHARS = "; | & $ ` ( ) < > newline"

-- Forward declarations: these helpers refer to each other, so their definition
-- order in this file is not significant.
local emit, check_sink, build_trace, snippet_at, code_confidence, return_taint

-- ------------------------------------------------------------ taint sets
-- A taint set is a set of descriptors keyed by id so union is cheap and
-- idempotent. Descriptors carry a stable id, a description and a line.

local function new_set()
   return {}
end

local function set_add(set, descriptor)
   if set[descriptor.id] then return false end
   set[descriptor.id] = descriptor
   return true
end

-- A shell quoting helper neutralizes the data for a shell sink, but not for
-- loadstring. Rather than a second taint set, a sanitized descriptor keeps the
-- same source but is marked as quoted, so the sink can tell the difference.
local function quoted_descriptor(descriptor)
   if descriptor.shell_quoted then return descriptor end
   return {
      id = descriptor.id .. "|quoted",
      name = descriptor.name,
      line = descriptor.line,
      confidence = descriptor.confidence,
      shell_quoted = true,
   }
end

local function any_unquoted(descriptors)
   for _, descriptor in ipairs(descriptors) do
      if not descriptor.shell_quoted then return true end
   end
   return false
end

local function any_quoted(descriptors)
   for _, descriptor in ipairs(descriptors) do
      if descriptor.shell_quoted then return true end
   end
   return false
end

-- Does a function body look like shell quoting?
--
-- It has to actually quote: a literal that is a single-quoted shell word, or a
-- gsub whose pattern is the doubled-quote escape. Merely containing an
-- apostrophe is not enough -- `log_it(s)` writing "user's input" is not a
-- quoting helper, and treating it as one would hide a real injection.
local function looks_like_shell_quote(node, depth)
   depth = depth or 0
   if depth > 24 or type(node) ~= "table" then return false end
   if node.tag == "String" then
      local text = node[1]
      if type(text) == "string" then
         if #text >= 2 and text:sub(1, 1) == "'" and text:sub(-1) == "'" then
            return true
         end
         if text:find("''", 1, true) or text:find("\\'") then
            return true
         end
      end
   elseif node.tag == "Call" or node.tag == "Invoke" then
      local callee = node[1]
      if callee and callee.tag == "Index" and callee[2] and callee[2][1] == "gsub" then
         for index = 2, #node do
            local argument = node[index]
            if argument and argument.tag == "String" and type(argument[1]) == "string" then
               if argument[1]:find("''", 1, true) or argument[1]:find("\\'") then
                  return true
               end
            end
         end
      end
   end
   for index = 1, #node do
      local child = node[index]
      if type(child) == "table" then
         if child.tag then
            if looks_like_shell_quote(child, depth + 1) then return true end
         else
            for _, sub in ipairs(child) do
               if type(sub) == "table" and sub.tag and looks_like_shell_quote(sub, depth + 1) then
                  return true
               end
            end
         end
      end
   end
   return false
end

local function set_union_into(target, other)
   local changed = false
   for _, descriptor in pairs(other) do
      if set_add(target, descriptor) then changed = true end
   end
   return changed
end

local function field_set(fields, key)
   local set = fields[key]
   if not set then
      set = new_set()
      fields[key] = set
   end
   return set
end

local function set_is_empty(set)
   return next(set) == nil
end

local function set_list(set)
   local out = {}
   for _, descriptor in pairs(set) do out[#out + 1] = descriptor end
   table.sort(out, function(a, b)
      if a.line ~= b.line then return (a.line or 0) < (b.line or 0) end
      return tostring(a.id) < tostring(b.id)
   end)
   return out
end

-- ------------------------------------------------------------ state

local function new_state()
   return {
      value_taint = setmetatable({}, {__mode = "k"}),  -- luacheck value -> taint set
      global_taint = {},                              -- dotted global path -> taint set
      table_fields = setmetatable({}, {__mode = "k"}), -- Table node -> {key -> taint set}
      global_tables = {},                              -- global name -> Table node
      findings = {},
      reported = {},                                  -- dedupe: one finding per site
      approx = false,                                 -- reduced-precision mode
      param_taint = setmetatable({}, {__mode = "k"}),   -- formal parameter -> taint set
      declared_sources = {},                            -- var name -> true
      declared_confidence = "high",
      var_taint = setmetatable({}, {__mode = "k"}),   -- approx mode: var -> taint set
   }
end

-- ------------------------------------------------------------ path resolution

-- Dotted path of a callee, e.g. "os.execute". Returns nil when the base is
-- dynamic (a local holding a table, an index by a variable, ...).
local function id_path(node)
   if node.tag == "Id" then
      return node[1]
   elseif node.tag == "Index" then
      local base = id_path(node[1])
      if base and node[2] and node[2].tag == "String" then
         return base .. "." .. node[2][1]
      end
   end
end

-- Resolve a callee expression to a path, following locals to the functions they
-- were assigned when we can, so `local run = os.execute; run(cmd)` still matches.
local function callee_path(node, item, state, depth)
   if depth > 8 then return nil end

   if node.tag == "Invoke" then
      local base = callee_path(node[1], item, state, depth + 1)
      local method = node[2] and node[2][1]
      if base and method then return base .. ":" .. method end
      return method
   end

   if node.tag == "Paren" then
      return callee_path(node[1], item, state, depth + 1)
   end

   -- `require("ffi").C` names the ffi module, not an anonymous value.
   if node.tag == "Call" then
      local required = callee_path(node[1], item, state, depth + 1)
      if required == "require" then
         local argument = node[2]
         if argument and argument.tag == "String" then
            return platform_api.module_name(argument[1]) or argument[1]
         end
      end
      return nil
   end

   -- Resolve a field access through the base's own definition, so
   -- `local C = ffi.C; C.system(x)` is recognised as `ffi.C.system(x)`.
   if node.tag == "Index" and node[2] and node[2].tag == "String" then
      local base = callee_path(node[1], item, state, depth + 1)
      if base then
         return base .. "." .. node[2][1]
      end
      return nil
   end

   local direct = id_path(node)
   if direct and not (node.tag == "Id" and node.var) then
      return direct
   end

   if node.tag == "Id" and node.var and item then
      local values = item.used_values and item.used_values[node.var]
      local fallback
      for _, value in ipairs(values or {}) do
         local value_node = value.node
         if value_node and value_node.tag == "Function" and value_node.name then
            return value_node.name
         elseif value_node and (value_node.tag == "Index" or value_node.tag == "Call") then
            -- `local C = ffi.C` then `C.system(...)` is `ffi.C.system`, and
            -- `local json = require("luci.jsonc")` then `json.parse(...)` is
            -- `jsonc.parse`. The comparison guards the case where resolving
            -- through the definition gives back the same name we started with.
            local via_local = callee_path(value_node, item, state, depth + 1)
            local own_name = value_node[1] and value_node[1].tag == "Id"
               and value_node[1][1] or nil
            if via_local and via_local ~= own_name then
               return via_local
            end
            fallback = fallback or via_local
         end
      end
      return fallback or node[1]
   end

   return direct
end

-- The Table node a base expression refers to, following locals and globals.
local function resolve_table_node(base, item, state)
   if not base then return nil end
   if base.tag == "Table" then return base end

   if base.tag == "Id" then
      if base.var then
         -- Reaching definitions first: this keeps table identity flow-sensitive.
         if item and item.used_values then
            for _, value in ipairs(item.used_values[base.var] or {}) do
               if value.node and value.node.tag == "Table" then return value.node end
            end
         end

         -- Fallback for the module pattern, `M.go = function() ... M ... end`.
         -- luacheck deliberately leaves an upvalue access unresolved there, to
         -- avoid reasoning about a self-referential table, so there is no
         -- reaching definition to read. We resolve the table's identity from the
         -- variable's definitions instead, and only when they all name the same
         -- table: a variable that is reassigned to a different table is left
         -- unresolved rather than resolved wrongly.
         local single = nil
         for _, value in ipairs(base.var.values or {}) do
            if value.node and value.node.tag == "Table" then
               if single and single ~= value.node then return nil end
               single = value.node
            end
         end
         if single then return single end
      else
         return state.global_tables[base[1]]
      end
   end

   if base.tag == "Index" then
      local outer = resolve_table_node(base[1], item, state)
      local fields = outer and state.table_fields[outer]
      if fields and base[2] and base[2].tag == "String" and fields.nodes then
         return fields.nodes[base[2][1]]
      end
   end

   return nil
end

local function table_fields_of(base, item, state)
   local table_node = resolve_table_node(base, item, state)
   if not table_node then return nil end
   local fields = state.table_fields[table_node]
   if not fields then
      fields = {}
      state.table_fields[table_node] = fields
   end
   return fields
end

-- ------------------------------------------------------------ expressions

local taint_of_expr

-- Taint of a variable at a given item: union over the reaching definitions.
-- When flow-sensitive dataflow was skipped, fall back to the last assignment
-- seen in file order, which is what a single forward pass can know.
local function taint_of_var(node, item, state)
   local result = new_set()
   local var = node.var

   if state.approx and var then
      set_union_into(result, state.var_taint[var] or new_set())
      return result
   end

   -- A name the operator declared a source of untrusted data.
   if var and state.declared_sources[var.name] then
      set_add(result, {
         id = "declared:" .. var.name,
         name = "declared source " .. var.name,
         line = var.node and var.node.line,
         confidence = state.declared_confidence,
      })
   end

   if var and state.arg_binding and state.arg_binding[var] then
      -- Taint bound to this formal parameter for the call currently being
      -- evaluated by taint_of_call. Takes precedence over param_taint, which
      -- is the context-insensitive merge over all call sites.
      set_union_into(result, state.arg_binding[var])
   elseif var and state.param_taint[var] then
      -- Taint bound to a formal parameter by the interprocedural pass. A
      -- parameter has no reaching definition of its own, so this is the only
      -- way an argument's taint reaches the body.
      set_union_into(result, state.param_taint[var])
   end

   if var and item and item.used_values then
      for _, value in ipairs(item.used_values[var] or {}) do
         set_union_into(result, state.value_taint[value] or new_set())
      end
   elseif not var then
      set_union_into(result, state.global_taint[node[1]] or new_set())
   end

   return result
end

local function taint_of_index(node, item, state, depth)
   local result = new_set()
   set_union_into(result, taint_of_expr(node[1], item, state, depth + 1))
   set_union_into(result, taint_of_expr(node[2], item, state, depth + 1))

   -- Table field taint: t.cmd = x, then use t.cmd
   local fields = table_fields_of(node[1], item, state)
   local table_node = resolve_table_node(node[1], item, state)
   if fields and node[2] and node[2].tag == "String" then
      set_union_into(result, fields[node[2][1]] or new_set())
   end

   return result
end

local function args_of(node)
   local args = {}
   if node.tag == "Call" then
      for i = 2, #node do args[#args + 1] = node[i] end
   elseif node.tag == "Invoke" then
      for i = 3, #node do args[#args + 1] = node[i] end
   end
   return args
end

-- A call expression: sources introduce taint, propagators pass it through.
local function taint_of_call(node, item, state, depth)
   local result = new_set()
   local callee = node.tag == "Invoke" and node[1] or node[1]
   local path = callee_path(callee, item, state, depth)
   local args = args_of(node)

   -- A method call on an object we cannot name still has a method name, and
   -- `handle:read("*a")` is a file read whoever the handle is. Both spellings
   -- reach us: a colon call as an Invoke node, and a field call on a value we
   -- could not resolve as an Index callee. The base path of a method call is
   -- usually just the variable holding the object, so it says nothing; the
   -- method name is the part that carries meaning.
   local method_name
   if node.tag == "Invoke" then
      method_name = node[2] and node[2][1]
   elseif node[1] and node[1].tag == "Index" and node[1][2] and node[1][2].tag == "String" then
      method_name = node[1][2][1]
   end
   -- Hoisted so the fallback (below the `if path then` block) can read it.
   local sanitized

   if method_name then
      local by_method = platform_api.match_method_source(method_name)
      if by_method then
         set_add(result, {
            id = by_method.id, name = by_method.name,
            line = node.line, confidence = by_method.confidence,
         })
         return result
      end
   end

   if path then
      local source = platform_api.match_source(path)
      if source then
         set_add(result, {
            id = source.id,
            name = source.name,
            line = node.line,
            confidence = source.confidence,
         })
         return result
      end

      local propagator = platform_api.match_propagator(path)
      if propagator then
         for _, index in ipairs(propagator.arg or {}) do
            if args[index] then
               local from = taint_of_expr(args[index], item, state, depth + 1)
               if platform_api.is_sanitizer("shell", path) then
                  -- A local quoting helper, recognised by its body.
                  for _, descriptor in pairs(from) do
                     set_add(result, quoted_descriptor(descriptor))
                  end
               else
                  set_union_into(result, from)
               end
            end
         end
      end

      -- A function defined in this file that quotes its argument neutralizes
      -- taint for shell sinks.
      sanitized = platform_api.is_sanitizer("shell", path)
      if not sanitized and node[1] and node[1].tag == "Id" and node[1].var then
         for _, value in ipairs((item.used_values or {})[node[1].var] or {}) do
            if value.node and value.node.tag == "Function" and looks_like_shell_quote(value.node) then
               sanitized = true
               break
            end
         end
      end
      if sanitized and not propagator then
         for index, arg in ipairs(args) do
            for _, descriptor in pairs(taint_of_expr(arg, item, state, depth + 1)) do
               set_add(result, quoted_descriptor(descriptor))
            end
         end
      end
   end

   -- Anything else: the result can still carry taint from the callee itself
   -- (e.g. `local f = tainted_module`), so include the callee's taint.
   if node.tag ~= "Invoke" then
      set_union_into(result, taint_of_expr(callee, item, state, depth + 1))
   end

   -- Follow a local function's return value: bind each formal parameter to the
   -- taint of the matching argument at this call site, then propagate through
   -- the function's return expressions as context-sensitive bindings. A guard
   -- on state.returning[fn] prevents unbounded recursion on a function that
   -- returns its own call.
   -- ponytail: a module field (M.id) in the same file is followed too;
   -- a cross-file return is not (that needs --whole-program's
   -- resolve_external).
   if not sanitized and node.tag == "Call"
         and node[1] and node[1].tag == "Id" and node[1].var
         and item and item.used_values then
      local fn
      for _, value in ipairs(item.used_values[node[1].var]) do
         if value.node and value.node.tag == "Function" then
            fn = value.node
            break
         end
      end
      if fn and state.returns and state.returns[fn] and not state.returning[fn] then
         local arg_nodes = args_of(node)
         local arg_taints = {}
         for i = 1, #arg_nodes do
            arg_taints[i] = taint_of_expr(arg_nodes[i], item, state, depth + 1)
         end
         set_union_into(result, return_taint(fn, arg_taints, state, depth))
      end
   elseif not sanitized and node.tag == "Call"
         and node[1] and node[1].tag == "Index"
         and node[1][1] and node[1][1].tag == "Id" and node[1][1].var
         and node[1][2] and node[1][2].tag == "String"
         and state and state.field_functions then
      -- A module field (M.id) in this same file: resolve it to its function
      -- value, if there is exactly one.
      local fn = (state.field_functions[node[1][1].var] or {})[node[1][2][1]]
      if fn then
         local arg_nodes = args_of(node)
         local arg_taints = {}
         for i = 1, #arg_nodes do
            arg_taints[i] = taint_of_expr(arg_nodes[i], item, state, depth + 1)
         end
         if looks_like_shell_quote(fn) then
            -- A quoting field helper neutralizes the shell sink: each argument's
            -- taint is quoted rather than propagated raw, and the return is not
            -- followed so the sink marks the call shell-quoted.
            for _, arg_taint in ipairs(arg_taints) do
               for _, descriptor in pairs(arg_taint) do
                  set_add(result, quoted_descriptor(descriptor))
               end
            end
         elseif state.returns and state.returns[fn]
               and not state.returning[fn] then
            set_union_into(result, return_taint(fn, arg_taints, state, depth))
         end
      end
   end

   -- Cross-file return: a require edge nested in an expression (e.g.
   -- os.execute(m.id(http.formvalue("h"))) where m.id lives in another file).
   -- The only local resolution that applies is `node[1].var`, so a call through
   -- a variable bound to a required module -- m.id(x) -- falls through both
   -- branches above. When the whole-program pass has wired in a resolver, ask
   -- it for the target function and follow its return the same way a local or
   -- field function is followed, just in the target file's state.
   if not sanitized and state.resolve_external
         and node.tag == "Call" and node[1] then
      local fn, target_state, target_path = state.resolve_external(node, item)
      if fn and target_state.returns and target_state.returns[fn]
            and not target_state.returning[fn] then
         local arg_nodes = args_of(node)
         local arg_taints = {}
         for i = 1, #arg_nodes do
            arg_taints[i] = taint_of_expr(arg_nodes[i], item, state, depth + 1)
         end
         if looks_like_shell_quote(fn) then
            -- A quoting helper in another file neutralises the shell sink:
            -- each argument's taint is quoted rather than propagated raw.
            for _, arg_taint in ipairs(arg_taints) do
               for _, descriptor in pairs(arg_taint) do
                  set_add(result, quoted_descriptor(descriptor))
               end
            end
            if state.on_external_return then
               state.on_external_return(new_set(), arg_taints, target_path)
            end
         else
            local returned = return_taint(fn, arg_taints, target_state, depth + 1)
            if state.on_external_return then
               state.on_external_return(returned, arg_taints, target_path)
            end
            set_union_into(result, returned)
         end
      end
   end

   return result
end

taint_of_expr = function(node, item, state, depth)
   depth = depth or 0
   if depth > 32 or type(node) ~= "table" then
      return new_set()
   end

   local tag = node.tag
   if tag == "Id" then
      return taint_of_var(node, item, state)
   elseif tag == "Index" then
      return taint_of_index(node, item, state, depth)
   elseif tag == "Call" or tag == "Invoke" then
      return taint_of_call(node, item, state, depth)
   elseif tag == "Op" then
      local result = new_set()
      if node[2] then set_union_into(result, taint_of_expr(node[2], item, state, depth + 1)) end
      if node[3] then set_union_into(result, taint_of_expr(node[3], item, state, depth + 1)) end
      return result
   elseif tag == "Paren" then
      return taint_of_expr(node[1], item, state, depth + 1)
   elseif tag == "Table" then
      local result = new_set()
      for _, pair_node in ipairs(node) do
         if pair_node.tag == "Pair" then
            set_union_into(result, taint_of_expr(pair_node[2], item, state, depth + 1))
         else
            set_union_into(result, taint_of_expr(pair_node, item, state, depth + 1))
         end
      end
      return result
   end

   return new_set()
end

-- Evaluate a function's return taint given the taint of its call-site arguments.
-- Binds each formal parameter to its argument's taint (context-sensitive), walks
-- the function's recorded return expressions, memoises the result, and restores
-- the caller's binding state. Returns a new taint set.
return_taint = function(fn, arg_taints, state, depth)
   local result = new_set()
   if not (fn and state.returns and state.returns[fn]) or state.returning[fn] then
      return result
   end

   local formals = {}
   for _, arg in ipairs(fn[1] or {}) do
      if arg.var then formals[#formals + 1] = arg.var end
   end

   -- Context-sensitive bindings: each formal -> its argument's taint.
   local saved = {}
   for i, var in ipairs(formals) do
      saved[i] = state.arg_binding[var]
      local arg_taint = arg_taints[i]
      if not arg_taint then arg_taint = new_set() end
      state.arg_binding[var] = arg_taint
   end
   state.returning[fn] = true

   -- Cache key: sorted descriptor ids of each bound argument, joined
   -- by formals with ";", so the same argument taint rebinds at once.
   local parts = {}
   for i, var in ipairs(formals) do
      local ids = {}
      for _, d in pairs(arg_taints[i] or new_set()) do ids[#ids + 1] = d.id end
      table.sort(ids)
      parts[i] = table.concat(ids, ",")
   end
   local key = table.concat(parts, ";")

   local cached = state.return_cache[fn] and state.return_cache[fn][key]
   if cached then
      set_union_into(result, cached)
   else
      local ret = new_set()
      local ok, err = pcall(function()
         for _, r in ipairs(state.returns[fn]) do
            set_union_into(ret, taint_of_expr(r.node, r.item, state, depth + 1))
         end
      end)
      if not ok then
         state.returning[fn] = nil
         for i, var in ipairs(formals) do
            state.arg_binding[var] = saved[i]
         end
         error(err)
      end
      -- Store a copy so later mutation of result cannot corrupt the cache.
      local copy = new_set()
      for _, d in pairs(ret) do copy[d.id] = d end
      if not state.return_cache[fn] then state.return_cache[fn] = {} end
      state.return_cache[fn][key] = copy
      set_union_into(result, ret)
   end

   state.returning[fn] = nil
   for i, var in ipairs(formals) do
      state.arg_binding[var] = saved[i]
   end

   return result
end

-- Record taint written into a table constructor or a field assignment.
-- Record the taint a write puts somewhere: a table constructor's fields, or a
-- single field assignment. `value_node` is what is being written, which is not
-- the left-hand side itself: reading the field back through the left-hand side
-- would just find the empty set we are creating.
local function record_table_write(node, value_node, item, state, depth)
   depth = depth or 0
   if depth > 16 or type(node) ~= "table" then return end
   local tag = node.tag

   if tag == "Table" then
      for _, pair_node in ipairs(node) do
         if pair_node.tag == "Pair" and pair_node[1] and pair_node[1].tag == "String" then
            local fields = state.table_fields[node]
            if not fields then
               fields = {}
               state.table_fields[node] = fields
            end
            set_union_into(field_set(fields, pair_node[1][1]),
               taint_of_expr(pair_node[2], item, state, depth + 1))
         end
      end
   elseif tag == "Index" and node[2] and node[2].tag == "String" then
      local fields = table_fields_of(node[1], item, state)
      if fields and value_node then
         set_union_into(field_set(fields, node[2][1]),
            taint_of_expr(value_node, item, state, depth + 1))
      end
   elseif tag == "Paren" then
      record_table_write(node[1], value_node, item, state, depth + 1)
   end
end

-- ------------------------------------------------------------ sinks

emit = function(state, spec, node, chstate, extra)
   local code = codes.get(spec.code)
   if not code then return end

   -- The propagation loop revisits each item until nothing changes, so the same
   -- call site is checked many times. One finding per site.
   local column = node.offset - (chstate.line_offsets[node.line] or 0) + 1
   local key = table.concat({spec.code, tostring(node.line), tostring(column),
      tostring(spec.name or spec.pattern)}, "|")
   if state.reported[key] then return end
   state.reported[key] = true

   local column = node.offset - (chstate.line_offsets[node.line] or 0) + 1
   local end_column = column + (node.end_offset - node.offset)

   local finding = {
      code = spec.code,
      line = node.line,
      column = math.max(1, column),
      end_column = math.max(1, end_column),
      severity = spec.severity or code.severity,
      confidence = extra and extra.confidence or code.confidence or "medium",
      cwe = code.cwe,
      name = spec.name or spec.pattern,
      sink = spec.pattern,
   }
   for key, value in pairs(extra or {}) do
      if key ~= "confidence" then finding[key] = value end
   end

   finding.message = codes.render(code, finding)

   state.findings[#state.findings + 1] = finding
   return finding
end

-- Ordered source -> sink description, used by SARIF codeFlows and the terminal
-- report. The line numbers come from the taint descriptors, so this is a real
-- path rather than a decoration.
build_trace = function(node, sources)
   local trace = {}
   for _, source in ipairs(sources) do
      trace[#trace + 1] = {kind = "source", name = source.display_id or source.id,
         line = source.line}
   end
   trace[#trace + 1] = {kind = "sink", name = nil, line = node.line}
   return trace
end

-- API shapes (FFI use, computed module names) are reported on their own: the
-- fact that the call happens is the finding, whatever its argument holds.
local function check_shape(node, item, state, chstate, opts)
   if opts.report_sink_shapes == false then return end
   local path = callee_path(node[1], item, state, 0)
   if not path then return end
   local shape = platform_api.match_shape(path)
   if not shape then return end

   -- 705 and 706 are about a name computed at runtime. A constant module name
   -- is the normal case and is not a finding.
   if shape.code == "705" or shape.code == "706" then
      local arg = args_of(node)[1]
      if arg and not const_eval.is_constant(arg) then
         local arg_taint = taint_of_expr(arg, item, state, 0)
         emit(state, {code = shape.code, pattern = shape.pattern}, node, chstate, {
            name = path,
            confidence = set_is_empty(arg_taint) and "low" or "high",
         })
      end
      return
   end

   emit(state, {code = shape.code, pattern = shape.pattern}, node, chstate, {name = path})
end

-- Check one call expression against the sink registry.
--
-- A sink has two identities: the code for "this argument is dynamic" and the
-- code for "this argument is dynamic *and* carries untrusted data". Proven
-- untrusted flow is the finding that matters, so it wins.
local function check_sink(node, item, state, chstate, opts)
   local callee = node[1]
   local path = callee_path(callee, item, state, 0)
   if not path then return end

   local sink = platform_api.match_sink(path)
   if not sink then return end

   local args = args_of(node)
   local kind = sink.kind or "shell"

   -- Writing attacker data into a configuration that a service later executes is
   -- a different finding (722) with the path it can reach, so the firmware rule
   -- module owns it.
   if kind == "config" then
      return
   end

   if sink.kind == "expose" then
      if opts.report_sink_shapes ~= false then
         emit(state, sink, node, chstate, {name = path})
      end
      return
   end

   local tainted_args = {}
   for _, index in ipairs(sink.arg or {1}) do
      local arg = args[index]
      if arg then
         local arg_taint = taint_of_expr(arg, item, state, 0)
         if not set_is_empty(arg_taint) then
            tainted_args[#tainted_args + 1] = {index = index, node = arg, taint = arg_taint}
         end
      end
   end

   for _, tainted_arg in ipairs(tainted_args) do
      local sources = set_list(tainted_arg.taint)
      for _, descriptor in ipairs(sources) do
         descriptor.display_id = (descriptor.id:gsub("|quoted$", ""))
      end
      local source = sources[1]
      local taint_spec = {
         code = kind == "dyncode" and "710" or "709",
         kind = kind,
         pattern = sink.pattern,
      }
      emit(state, taint_spec, node, chstate, {
         name = path,
         confidence = source.confidence or code_confidence(taint_spec.code),
         source = source.display_id or source.id,
         sources = sources,
         trace = build_trace(tainted_arg.node, sources),
         snippet = snippet_at(chstate, tainted_arg.node),
         sanitizer = (not any_unquoted(sources)) and "shell-quoted" or nil,
      })

      -- 712 is the partially quoted case: some of the untrusted data was passed
      -- through a quoting helper and some was not. That is where an operator
      -- assumed the command was safe, so it gets its own finding naming the
      -- characters that break out. A wholly unquoted command is already the
      -- critical 709, and a wholly quoted one is 709 with the flow noted, so
      -- neither needs a second finding.
      if kind == "exec" and any_unquoted(sources) and any_quoted(sources) then
         emit(state, {code = "712", pattern = sink.pattern, name = path}, node, chstate, {
            name = path,
            confidence = source.confidence or code_confidence("712"),
            source = source.id,
            sources = sources,
            trace = build_trace(tainted_arg.node, sources),
            metachars = SHELL_METACHARS,
         })
      end
   end

   if #tainted_args > 0 then return end

   -- No known taint, but is the argument actually constant? If we cannot prove
   -- it is, the call is still an execution sink fed by something unknown.
   if opts.report_dynamic_sinks == false then return end

   for _, index in ipairs(sink.arg or {1}) do
      local arg = args[index]
      if arg and not const_eval.is_constant(arg) then
         emit(state, sink, node, chstate, {name = path, confidence = "low"})
      end
   end
end

code_confidence = function(code)
   local spec = codes.get(code)
   return spec and spec.confidence or "medium"
end

snippet_at = function(chstate, node)
   local source = chstate.source
   if not source then return nil end
   local from = math.max(1, node.offset)
   local to = math.min(#source, node.end_offset)
   if to <= from then return nil end
   return (source:sub(from, to):gsub("%s+", " "))
end
-- ------------------------------------------------------------ driver

-- Propagate taint through the whole file to a fixed point. Taint only ever
-- grows, so the iteration is monotone and the iteration cap makes termination
-- obvious rather than accidental.
local function propagate(chstate, state, opts)
   for _ = 1, MAX_ITERATIONS do
      local changed = false
      -- Cached return taint is only valid for the current value_taint snapshot:
      -- taint only grows, so a cached answer computed before growth may be stale.
      state.return_cache = {}

      for _, line in ipairs(chstate.lines) do
         for _, item in ipairs(line.items) do
            local tag = item.tag

            if tag == "Local" or tag == "Set" or tag == "OpSet" then
               -- Field writes (`M.cmd = x`) never appear in set_variables, because
               -- only plain locals get a value object there.
               for index, lhs_node in ipairs(item.lhs or {}) do
                  local written = item.rhs and item.rhs[index]
                  if lhs_node.tag == "Index" then
                     record_table_write(lhs_node, written, item, state, 0)
                  end
               end

               for _, value in pairs(item.set_variables or {}) do
                  local value_taint = taint_of_expr(value.node, item, state, 0)

                  if not set_is_empty(value_taint) then
                     local existing = state.value_taint[value]
                     if not existing then
                        existing = new_set()
                        state.value_taint[value] = existing
                     end
                     if set_union_into(existing, value_taint) then changed = true end
                  end

                  if value.node then
                     record_table_write(value.node, nil, item, state, 0)
                  end
               end

               -- Globals have no reaching-definition model, so track them by name.
               for index, lhs_node in ipairs(item.lhs or {}) do
                  if lhs_node.tag == "Id" and not lhs_node.var and item.rhs then
                     local rhs_node = item.rhs[index]
                     if rhs_node and rhs_node.tag == "Table" then
                        state.global_tables[lhs_node[1]] = rhs_node
                        record_table_write(rhs_node, nil, item, state, 0)
                     end
                     local value_taint = taint_of_expr(item.rhs[1], item, state, 0)
                     if not set_is_empty(value_taint) then
                        local existing = state.global_taint[lhs_node[1]]
                        if not existing then
                           existing = new_set()
                           state.global_taint[lhs_node[1]] = existing
                        end
                        if set_union_into(existing, value_taint) then changed = true end
                     end
                  elseif lhs_node.tag == "Index" and lhs_node[1].tag == "Id"
                        and not lhs_node[1].var and lhs_node[2] and lhs_node[2].tag == "String" then
                     local path = lhs_node[1][1] .. "." .. lhs_node[2][1]
                     local existing = state.global_taint[path]
                     if not existing then
                        existing = new_set()
                        state.global_taint[path] = existing
                     end
                     if item.rhs
                           and set_union_into(existing, taint_of_expr(item.rhs[1], item, state, 0)) then
                        changed = true
                     end
                  end
               end
            elseif tag == "Eval" then
               local node = item.node
               if node and (node.tag == "Call" or node.tag == "Invoke") then
                  check_shape(node, item, state, chstate, opts)
                  check_sink(node, item, state, chstate, opts)
               end
               if node then
                  record_table_write(node, nil, item, state, 0)
               end
            end
         end
      end

      if not changed then
         return
      end
   end
end

function taint.run(chstate, opts, existing_state)
   opts = opts or {}
   local state = existing_state or new_state()
   state.declared_sources = {}
   state.declared_confidence = opts.source_confidence or "high"
   for _, name in ipairs(opts.sources or {}) do
      state.declared_sources[name] = true
   end
   state.approx = chstate.resolved_locals == false
   if existing_state then
      state.approx = false
   end

   -- Index each local function's return expressions once per chstate. run()
   -- is called more than once with the same state (the interprocedural pass
   -- re-runs propagation), so build this lazily and cache it on the state.
   if not state.returns then
      state.returns = {}
      state.field_functions = {}
      for _, line in ipairs(chstate.lines) do
         if line.node and line.node.tag == "Function" then
            local exprs = {}
            for index, item in ipairs(line.items) do
               if item.tag == "Noop" and type(item.node) == "table"
                     and item.node.tag == "Return" then
                  for next_index = index + 1, #line.items do
                     local following = line.items[next_index]
                     if following.tag ~= "Eval" then break end
                     if type(following.node) == "table" then
                        exprs[#exprs + 1] = {node = following.node, item = following}
                     end
                  end
               end
            end
            state.returns[line.node] = exprs
         end

         -- Index a module field's function value, so a call through a field
         -- access (M.id(...)) can follow the same local-function return taint
         -- as a plain local call (id(...)). A var/key with two different
         -- function definitions is ambiguous and recorded as false so it is
         -- not followed.
         for _, item in ipairs(line.items) do
            if item.tag == "Set" or item.tag == "Local" then
               for i = 1, #(item.lhs or {}) do
                  local lhs_node = item.lhs[i]
                  if lhs_node and lhs_node.tag == "Index"
                        and lhs_node[1] and lhs_node[1].tag == "Id"
                        and lhs_node[1].var
                        and lhs_node[2] and lhs_node[2].tag == "String"
                        and item.rhs then
                     local rhs_node = item.rhs[i]
                     if rhs_node and rhs_node.tag == "Function" then
                        local per_var = state.field_functions[lhs_node[1].var]
                        if not per_var then
                           per_var = {}
                           state.field_functions[lhs_node[1].var] = per_var
                        end
                        local key = lhs_node[2][1]
                        if per_var[key] == nil then
                           per_var[key] = rhs_node
                        elseif per_var[key] ~= rhs_node then
                           per_var[key] = false
                        end
                     end
                  end
               end
            end
         end
      end
   end

   -- arg_binding: context-sensitive binding for the call currently being
   -- evaluated by taint_of_call; a map from var -> taint set. nil when none.
   state.arg_binding = state.arg_binding or {}
   -- returning[fn] = true while we are mid-evaluation of fn's returns, so a
   -- recursive call cannot descend into itself.
   state.returning = state.returning or {}
   -- return_cache: fn -> { [argkey] = taint_set }, memoising a function's
   -- return taint for a given binding of its arguments. Cleared every
   -- propagate iteration so cached answers cannot outlive value_taint growth.
   state.return_cache = state.return_cache or {}

   if state.approx then
      -- One forward pass. No loops, no closures, no reaching definitions: enough
      -- to follow a value from its assignment to a later use, and honest about
      -- being approximate, which the caller reports as 904.
      for _, line in ipairs(chstate.lines) do
         for _, item in ipairs(line.items) do
            if item.tag == "Local" or item.tag == "Set" or item.tag == "OpSet" then
               for index, lhs_node in ipairs(item.lhs or {}) do
                  local written = item.rhs and item.rhs[index]
                  if written and lhs_node.var then
                     local set = new_set()
                     set_union_into(set, taint_of_expr(written, item, state, 0))
                     state.var_taint[lhs_node.var] = set
                  end
               end
               for _, lhs_node in ipairs(item.lhs or {}) do
                  local written = item.rhs and item.rhs[1]
                  if lhs_node.tag == "Index" then
                     record_table_write(lhs_node, written, item, state, 0)
                  end
               end
            elseif item.tag == "Eval" then
               local node = item.node
               if node and (node.tag == "Call" or node.tag == "Invoke") then
                  check_shape(node, item, state, chstate, opts)
                  check_sink(node, item, state, chstate, opts)
               end
            end
         end
      end
      return state.findings
   end

   propagate(chstate, state, opts)
   return state.findings
end

-- Formal parameters of a function node.
taint.formals_of = function(function_node)
   local args = function_node[1] or {}
   local vars, varargs = {}, false
   for _, arg in ipairs(args) do
      if arg.tag == "Dots" then
         varargs = true
      elseif arg.var then
         vars[#vars + 1] = arg.var
      end
   end
   return vars, varargs
end

-- Arguments of a call expression, as nodes.
taint.args_of = args_of
taint.is_constant = const_eval.is_constant

-- The line whose items are a function's body, or nil.
-- One pass to find a function's line was O(lines) per call, and the
-- interprocedural pass does it once per call site. Index once instead.
local line_index_cache = {chstate = nil, by_node = nil}

local function line_index(chstate)
   if line_index_cache.chstate == chstate then return line_index_cache.by_node end
   local by_node = {}
   for _, line in ipairs(chstate.lines) do
      if line.node and not by_node[line.node] then
         by_node[line.node] = line
      end
   end
   line_index_cache.chstate, line_index_cache.by_node = chstate, by_node
   return by_node
end

taint.line_of_function = function(chstate, function_node)
   return line_index(chstate)[function_node]
end

-- Value objects bound to a formal parameter at the function's entry item.
taint.argument_values = function(item, var)
   if not (item and item.used_values) then return {} end
   return item.used_values[var] or {}
end

-- Exposed for the interprocedural pass, which reuses the same propagation.
taint.new_state = new_state
taint.of_expr = function(state, node, item) return taint_of_expr(node, item, state, 0) end
taint.return_taint = return_taint
taint.callee_path = function(node, item, state) return callee_path(node, item, state, 0) end
taint.add_value = function(state, value, set)
   local existing = state.value_taint[value]
   if not existing then
      existing = new_set()
      state.value_taint[value] = existing
   end
   return set_union_into(existing, set)
end
taint.set = taint

return taint
