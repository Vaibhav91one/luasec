-- Whole-program taint: follow a call out of the file it was written in.
--
-- The per-file passes see one file at a time, so a handler that reads a request
-- parameter and a helper in `util.lua` that executes it are two halves of one
-- bug that neither half can see. This pass joins them: it indexes the analyzed
-- files by the module names they define, resolves a call site's callee to a
-- Function node in another file, binds that function's formal parameters to the
-- argument taint at the call site, and re-propagates inside the callee until
-- nothing changes.
--
-- It takes the check states a per-file run has already built rather than parsing
-- anything itself, so it never re-reads a file and never executes one. Nothing
-- here runs unless `analyze` is called, so the per-file results stand on their
-- own by default.
--
-- Taint crosses the boundary as parameter taint: the descriptors computed at the
-- call site are unioned into the callee's formal parameters, which is the
-- mechanism the intra-file interprocedural pass already uses, so everything the
-- taint engine propagates (concatenation, table fields, sanitizers) keeps
-- working inside the other file. Returns are followed in two shapes: a
-- local function's return value, and a module field's return value, both within
-- one file. Under --whole-program the return of a function in a module bound with
-- local m = require "mod" is followed too. Not followed: a method call (M:m),
-- a function passed as a value, require(...) called inline inside an expression,
-- and anything past the depth cap.
--
-- The finding belongs to the file that holds the sink. Every step of its trace
-- names the file that step is in, so a flow crossing three files says which
-- three rather than quoting three line numbers a reader cannot place.
local taint_engine = require "luadoctor.engine.taint"
local platform_api = require "luadoctor.registry.platform_api"

local whole_program = {}

-- Bounds. Each is reported when hit, because a whole-program run that stops
-- early is otherwise indistinguishable from a clean one in a report that only
-- lists what it found. They are read from `opts` so a caller can trade time for
-- reach, and so a test can reach a bound it would otherwise have to build a
-- hundred files to reach.
local MAX_ROUNDS = 8
local MAX_MODULES_PER_FILE = 32
local MAX_SITES_PER_FILE = 4096
local MAX_ALIAS_DEPTH = 4
local MAX_CHAIN = 16
-- The handlers one call through a route table may resolve to. A dispatcher over
-- a larger table binds the first ones and says the bound was hit.
local MAX_ROUTE_TARGETS = 64

local BOUNDS = {
   whole_program_max_rounds = MAX_ROUNDS,
   whole_program_max_modules = MAX_MODULES_PER_FILE,
   whole_program_max_sites = MAX_SITES_PER_FILE,
   whole_program_max_route_targets = MAX_ROUTE_TARGETS,
}

-- The configured bound for a name, never less than one: a bound of zero would
-- stop the pass before it starts, which is not a thing to configure.
local function bound_of(opts, name)
   local configured = tonumber(opts[name])
   if configured and configured >= 1 then return math.floor(configured) end
   return BOUNDS[name]
end

local CONFIDENCE_LADDER = {"certain", "high", "medium", "low"}

-- How a module name was matched, weakest first. A declaration the file makes
-- about itself (a preload entry, a `module` call) and a path suffix are both
-- facts about the scanned tree. A unique basename is an inference about the
-- loader's search path, and a finding resting on one says so.
local MATCH_RANK = {basename = 1, path = 2, ["module()"] = 3, preload = 4}

local function is_inference(match)
   return MATCH_RANK[match] == MATCH_RANK.basename
end

-- The weakest of two matches, so one hop resolved by path and another by
-- basename leaves the finding marked as the weaker of the two.
local function weaker_match(current, seen)
   if not current or MATCH_RANK[seen] < MATCH_RANK[current] then return seen end
   return current
end

-- One step down the confidence ladder, for a flow that leans on a file we only
-- analyzed approximately.
local function weaken(confidence)
   for index, level in ipairs(CONFIDENCE_LADDER) do
      if level == confidence then return CONFIDENCE_LADDER[index + 1] end
   end
   return confidence
end

local function count(map)
   local total = 0
   for _ in pairs(map or {}) do total = total + 1 end
   return total
end

-- ------------------------------------------------------------ shape helpers

-- The path components a module name is made of: `net/util.lua` is `net.util`.
local function path_components(path)
   local parts = {}
   for part in path:gmatch("[^/\\]+") do parts[#parts + 1] = part end
   local last = parts[#parts]
   if last then parts[#parts] = (last:gsub("%.lua$", "")) end
   return parts
end

-- Every name a file could be required as, most specific first. Lua's own search
-- path is not in the analyzed set, so matching a suffix of the path is the best
-- available claim, and a name two files both answer to is left unresolved.
local function candidate_names(path)
   local parts = path_components(path)
   local out = {}
   for start = 1, #parts do
      local name = table.concat(parts, ".", start, #parts)
      if name ~= "" then out[#out + 1] = name end
   end
   return out
end

-- `require` spells the same module with dots or with slashes; the index is keyed
-- by the dotted form of both.
local function normalize_module_name(name)
   if type(name) ~= "string" then return nil end
   local normalized = name:gsub("/", ".")
   if normalized == "" then return nil end
   return normalized
end

-- The literal module name of `require "name"`, or nil. A name computed at run
-- time names nothing an index can hold, and 705 already reports it.
local function require_name(node, depth)
   depth = depth or 0
   if depth > MAX_ALIAS_DEPTH or type(node) ~= "table" then return nil end
   if node.tag == "Call" then
      local callee = node[1]
      if not (type(callee) == "table" and callee.tag == "Id"
               and not callee.var and callee[1] == "require") then
         return nil
      end
      local argument = node[2]
      if type(argument) == "table" and argument.tag == "String"
            and type(argument[1]) == "string" then
         return argument[1]
      end
      return nil
   end
   if node.tag == "Paren" then return require_name(node[1], depth + 1) end
   return nil
end

-- The module name a `module "name"` statement declares, or nil. Lua 5.1's
-- `module` call is deprecated but half the firmware in the wild still uses it,
-- and it names the module without a `return` anywhere in sight: every top-level
-- definition after the call lands in that module's table.
local function declared_module_name(node)
   if type(node) ~= "table" or node.tag ~= "Call" then return nil end
   local callee = node[1]
   if not (type(callee) == "table" and callee.tag == "Id"
            and not callee.var and callee[1] == "module") then
      return nil
   end
   local argument = node[2]
   if type(argument) == "table" and argument.tag == "String"
         and type(argument[1]) == "string" then
      return argument[1]
   end
   return nil
end

-- The module name a `package.preload["name"] = function() end` entry defines.
local function preload_name(node)
   if type(node) ~= "table" or node.tag ~= "Index" then return nil end
   local base = node[1]
   if type(base) ~= "table" or base.tag ~= "Index" then return nil end
   if not (type(base[1]) == "table" and base[1].tag == "Id" and not base[1].var
            and base[1][1] == "package") then
      return nil
   end
   if not (type(base[2]) == "table" and base[2].tag == "String"
            and base[2][1] == "preload") then
      return nil
   end
   if type(node[2]) == "table" and node[2].tag == "String"
         and type(node[2][1]) == "string" then
      return node[2][1]
   end
   return nil
end

-- The node linearize hangs on the file's own top-level lines. It is neither nil
-- nor a Function node -- it is the argument list luacheck synthesizes for the
-- file -- so "is this line at the top level" is a comparison against it rather
-- than a nil check.
local function top_level_node(chstate)
   return chstate.top_line and chstate.top_line.node
end

-- The expressions a `return` statement hands back, for the block whose lines
-- carry `owner` as their node: a Function node, or the file's own top level.
-- linearize turns `return a, b` into a Noop carrying the Return node, one Eval
-- per returned expression, then the jump out of the block.
local function returns_of(chstate, owner)
   local out = {}
   for _, line in ipairs(chstate.lines) do
      if line.node == owner then
         local items = line.items
         for index, item in ipairs(items) do
            if item.tag == "Noop" and type(item.node) == "table"
                  and item.node.tag == "Return" then
               for next_index = index + 1, #items do
                  local following = items[next_index]
                  if following.tag ~= "Eval" then break end
                  if type(following.node) == "table" then out[#out + 1] = following.node end
               end
            end
         end
      end
   end
   return out
end

-- The Function node a name refers to, but only when every definition agrees: a
-- variable rebound to a different function resolves to nothing rather than to
-- the wrong one. This is what makes `M.run = helper` reach `helper`.
--
-- Memoized per variable, because a file that assigns the same name in many
-- places would otherwise re-walk that variable's value list once per use.
local function sole_function(file, node, depth)
   depth = depth or 0
   if depth > MAX_ALIAS_DEPTH or type(node) ~= "table" then return nil end
   if node.tag == "Function" then return node end
   if node.tag == "Paren" then return sole_function(file, node[1], depth + 1) end
   if node.tag == "Id" and node.var then
      local memo = file.sole_functions[node.var]
      if memo == nil then
         local only
         for _, value in ipairs(node.var.values or {}) do
            if value.node and value.node.tag == "Function" then
               if only and only ~= value.node then
                  only = false
                  break
               end
               only = value.node
            end
         end
         memo = {value = only or false}
         file.sole_functions[node.var] = memo
      end
      return memo.value or nil
   end
   return nil
end

-- The Table node a name refers to, under the same agreement rule. This is the
-- module table of `local M = {} ... return M`.
local function sole_table(file, node, depth)
   depth = depth or 0
   if depth > MAX_ALIAS_DEPTH or type(node) ~= "table" then return nil end
   if node.tag == "Table" then return node end
   if node.tag == "Paren" then return sole_table(file, node[1], depth + 1) end
   if node.tag == "Id" and node.var then
      local memo = file.sole_tables[node.var]
      if memo == nil then
         local only
         for _, value in ipairs(node.var.values or {}) do
            if value.node and value.node.tag == "Table" then
               if only and only ~= value.node then
                  only = false
                  break
               end
               only = value.node
            end
         end
         memo = {value = only or false}
         file.sole_tables[node.var] = memo
      end
      return memo.value or nil
   end
   return nil
end

-- Register a name for a function. Two different functions behind one name make
-- that name ambiguous, and binding to either would be a guess, so it is marked
-- false and every lookup through it declines.
local function add_field(fields, name, function_node)
   if type(name) ~= "string" or name == "" or not function_node then return end
   local existing = fields[name]
   if existing == false then return end
   if existing and existing ~= function_node then
      fields[name] = false
      return
   end
   fields[name] = function_node
end

-- ------------------------------------------------------------ per-file scan

-- One pass over a file's items collects everything the index needs, so no later
-- phase walks the AST again. Each phase below is linear in what this produced.
local function scan(file)
   local chstate = file.chstate
   file.index_writes = {}
   file.field_reads = {}
   file.preloads = {}
   file.functions = {}
   file.dotted = {}
   file.module_fields = {}
   file.sole_functions = {}
   file.sole_tables = {}
   file.global_tables = {}

   -- `module "name"` puts every top-level definition after it into that module,
   -- so the names it introduces have to be collected only from there on. The
   -- lines are already in source order.
   local declared

   for _, line in ipairs(chstate.lines) do
      file.items_scanned = (file.items_scanned or 0) + #line.items

      if line.node and line.node.tag == "Function"
            and type(line.node.name) == "string"
            and line.node.name:find(".", 1, true)
            and not line.node.name:find(":", 1, true) then
         -- `function gui.a.b.set(x)`: a function written onto a global table's
         -- field path, which another file reaches by the same dotted spelling.
         -- ponytail: a local of the same name in this file is indexed as a global
         -- too; a caller is only matched through a global root, so the cost is a
         -- wrong edge only when two files disagree about what `gui` is.
         add_field(file.dotted, line.node.name, line.node)
      end

      if line.node and line.node.tag == "Function"
            and type(line.node.name) == "string"
            and not line.node.name:find(".", 1, true) then
         -- A name with no dot in it is a name the file publishes at its own top
         -- level, which is what a file loaded into a shared global namespace
         -- adds to it.
         add_field(file.functions, line.node.name, line.node)
         if declared and line.parent == chstate.top_line then
            add_field(file.module_fields, line.node.name, line.node)
         end
      end

      for _, item in ipairs(line.items) do
         local tag = item.tag
         if tag == "Local" or tag == "Set" or tag == "OpSet" then
            for index, lhs in ipairs(item.lhs or {}) do
               local written = item.rhs and item.rhs[index]
               if type(written) == "table" and lhs.tag == "Id" and not lhs.var
                     and written.tag == "Table" and type(lhs[1]) == "string" then
                  -- `routes = {...}` at file level: a global table literal a
                  -- dispatcher may index. Two different literals make it false.
                  local existing = file.global_tables[lhs[1]]
                  if existing == nil then
                     file.global_tables[lhs[1]] = written
                  elseif existing ~= written then
                     file.global_tables[lhs[1]] = false
                  end
               elseif type(written) == "table" and lhs.tag == "Id" and lhs.var then
                  local module_name = require_name(written)
                  if module_name then
                     file.binds[lhs.var] = module_name
                  elseif written.tag == "Index" and type(written[2]) == "table"
                        and written[2].tag == "String" and type(written[1]) == "table" then
                     -- `local ping = util.ping`: a variable standing for one
                     -- member of a module, resolved once the direct binds are in.
                     file.field_reads[lhs.var] = {base = written[1], key = written[2][1]}
                  end
               elseif type(written) == "table" and lhs.tag == "Index"
                     and type(lhs[2]) == "table" and lhs[2].tag == "String" then
                  local name = preload_name(lhs)
                  if name and written.tag == "Function" then
                     file.preloads[#file.preloads + 1] = {name = name, factory = written}
                  elseif type(lhs[1]) == "table" and lhs[1].tag == "Id" then
                     file.index_writes[#file.index_writes + 1] = {
                        base = lhs[1], key = lhs[2][1], value = written,
                     }
                  end
               end
            end
         elseif tag == "Eval" and type(item.node) == "table" then
            local name = declared_module_name(item.node)
            if name and not declared then declared = name end
         end
      end
   end

   file.declared_module = declared
   return file
end

-- What a module name gives a caller: a table to read members off, a single
-- callable, or both.
local function surface_of(file, returned, extra_fields)
   local surface = {fields = {}}
   for name, function_node in pairs(extra_fields or {}) do
      if function_node then add_field(surface.fields, name, function_node) end
   end
   for _, node in ipairs(returned or {}) do
      local table_node = sole_table(file, node)
      if table_node then surface.table = table_node end
      local function_node = sole_function(file, node)
      if function_node then surface.callable = function_node end
   end

   if surface.table then
      -- `return { run = function() end }` states its members in the
      -- constructor; `M.run = function() end` states them after it.
      for _, pair_node in ipairs(surface.table) do
         if type(pair_node) == "table" and pair_node.tag == "Pair"
               and type(pair_node[1]) == "table" and pair_node[1].tag == "String" then
            add_field(surface.fields, pair_node[1][1], sole_function(file, pair_node[2]))
         end
      end
      for _, write in ipairs(file.index_writes) do
         if sole_table(file, write.base) == surface.table then
            add_field(surface.fields, write.key, sole_function(file, write.value))
         end
      end
   end

   return surface
end

-- ------------------------------------------------------------ module index

-- Build the index: module name -> the file and surface implementing it. Only
-- files in the analyzed set are in it, so a `require` of something the scan
-- never saw resolves to nothing rather than to a guess.
--
-- `opts.whole_program_basename` additionally lets a name resolve to the one
-- scanned file with that basename. It is a weaker claim: a path suffix says
-- this file is the `net.util` the loader would find, while a unique basename
-- says only that one file in the scan is called `util.lua`. It is off by
-- default because a scan of two overlapping trees makes it wrong, and because
-- the ambiguity check already refuses the case where two files share a name.
local function build_index(files, opts)
   local by_name = {}
   for _, file in ipairs(files) do
      for _, name in ipairs(candidate_names(file.path)) do
         local bucket = by_name[name]
         if not bucket then
            bucket = {}
            by_name[name] = bucket
         end
         bucket[#bucket + 1] = file
      end
   end

   local modules = {}
   local ambiguous = {}

   local function claim(name, entry)
      local key = normalize_module_name(name)
      if not key or modules[key] or ambiguous[key] then return end
      local bucket = by_name[key] or {}
      if #bucket > 1 then
         ambiguous[key] = #bucket
         return
      end
      if bucket[1] and bucket[1] ~= entry.file then
         -- A name the file claims but that another scanned file also answers to
         -- by path. Prefer the claimant: it said so in its own source.
         modules[key] = entry
         return
      end
      modules[key] = entry
   end

   for _, file in ipairs(files) do
      if #file.preloads > 0 then
         for _, preload in ipairs(file.preloads) do
            claim(preload.name, {
               file = file,
               kind = "preload",
               surface = surface_of(file, returns_of(file.chstate, preload.factory)),
            })
         end
      end
      file.own_surface = surface_of(file, returns_of(file.chstate, top_level_node(file.chstate)))
      if file.declared_module then
         claim(file.declared_module, {
            file = file,
            kind = "module()",
            surface = surface_of(file, file.own_returns, file.module_fields),
         })
      end
      for _, name in ipairs(candidate_names(file.path)) do
         claim(name, {file = file, kind = "path", surface = file.own_surface})
      end
   end

   local basenames = {}
   if opts.whole_program_basename then
      for _, file in ipairs(files) do
         local parts = path_components(file.path)
         local name = parts[#parts]
         local bucket = by_name[name] or {}
         if #bucket == 1 then basenames[name] = file end
      end
   end

   return {
      modules = modules, ambiguous = ambiguous, by_name = by_name, basenames = basenames,
   }
end

-- The file implementing a required name, and how that was established. Returns
-- nil when nothing in the analyzed set answers to the name, which is not a
-- finding: a `require` of a file outside the scan says nothing about this one.
local function entry_for(index, name)
   local key = normalize_module_name(name)
   if not key then return nil end
   local entry = index.modules[key]
   if entry then return entry end

   local basename = key:match("([^.]+)$")
   local file = basename and index.basenames[basename]
   if file and file.own_surface then
      return {file = file, kind = "basename", surface = file.own_surface}
   end
   return nil
end

-- Bind each `require` to the module it names. Aliases (`local ping = util.ping`)
-- need the direct binds in place first, and converge in a couple of passes.
local function resolve_binds(file, index)
   file.modules_of_var = {}

   for _ = 1, MAX_ALIAS_DEPTH do
      local changed = false

      for var, module_name in pairs(file.binds) do
         if not file.modules_of_var[var] then
            local entry = entry_for(index, module_name)
            if entry then
               file.modules_of_var[var] = {entry = entry, member = nil}
               changed = true
            end
         end
      end

      for var, read in pairs(file.field_reads) do
         if not file.modules_of_var[var] then
            local entry, member
            local module_name = require_name(read.base)
            if module_name then
               entry = entry_for(index, module_name)
               member = read.key
            elseif type(read.base) == "table" and read.base.tag == "Id"
                  and read.base.var then
               local binding = file.modules_of_var[read.base.var]
               if binding then
                  entry = binding.entry
                  member = binding.member
                     and (binding.member .. "." .. read.key)
                     or read.key
               end
            end
            if entry then
               file.modules_of_var[var] = {entry = entry, member = member}
               changed = true
            end
         end
      end

      if not changed then break end
   end
end

-- ------------------------------------------------------------ call sites

-- The module member a call site's callee names, or nil. Only the two shapes a
-- required module is reached through count: a local bound to the module
-- (`util.run(x)`) and the module's return value used directly
-- (`require("util").run(x)`).
local function member_of(file, callee, depth)
   depth = depth or 0
   if depth > MAX_ALIAS_DEPTH or type(callee) ~= "table" then return nil end

   if callee.tag == "Paren" then
      return member_of(file, callee[1], depth + 1)
   end

   if callee.tag == "Index" and type(callee[2]) == "table"
         and callee[2].tag == "String" then
      local key = callee[2][1]
      local base = callee[1]
      if type(base) == "table" and base.tag == "Id" and base.var then
         local binding = file.modules_of_var[base.var]
         if binding then
            if binding.member then
               return {entry = binding.entry, member = binding.member .. "." .. key}
            end
            return {entry = binding.entry, member = key}
         end
      end
      local module_name = require_name(base)
      if module_name then return {module = module_name, member = key} end
      return nil
   end

   if callee.tag == "Id" and callee.var then
      local binding = file.modules_of_var[callee.var]
      if binding and not binding.member then
         return {entry = binding.entry, member = nil}
      end
   end

   return nil
end

-- What a call node calls, as an expression `member_of` and `dotted_name` can
-- read. A method call `obj:m(x)` is the call `obj.m(obj, x)`, so its callee is
-- the field `obj.m`, built here as the Index node the dotted spelling would have.
local function callee_of(node)
   if node.tag == "Invoke" then
      return {tag = "Index", node[1], node[2]}
   end
   return node[1]
end

-- The arguments a call passes, in the order the callee's formals receive them.
-- A method call passes its receiver first, which is where `function M:m(cfg)`
-- has its implicit `self` and `M.m = function(self, cfg)` has its first formal.
local function call_args(node)
   local args = {}
   if node.tag == "Invoke" then
      args[1] = node[1]
      for position = 3, #node do args[#args + 1] = node[position] end
   else
      for position = 2, #node do args[#args + 1] = node[position] end
   end
   return args
end

-- The Function node a resolved member names, within one module.
local function function_for(entry, member)
   if not entry then return nil end
   local surface = entry.surface or {}
   if member == nil then return surface.callable end

   local direct = surface.fields[member]
   if direct then return direct end
   if direct == false then return nil end

   -- `M.run` is also known by the name_functions name `M.run`, and a caller may
   -- spell the member either way.
   local suffix = "." .. member
   local best
   for name, function_node in pairs(surface.fields) do
      if function_node and name:sub(-#suffix) == suffix then
         if not best or #name < #best.name then best = {name = name, node = function_node} end
      end
   end
   return best and best.node or nil
end

-- The lines of a file grouped by the function they belong to, built once and
-- only for a file something is actually asked about.
local function lines_by_function(file)
   if file.lines_by_function then return file.lines_by_function end
   local index = {}
   for _, line in ipairs(file.chstate.lines) do
      if type(line.node) == "table" and line.node.tag == "Function" then
         local bucket = index[line.node]
         if not bucket then
            bucket = {}
            index[line.node] = bucket
         end
         bucket[#bucket + 1] = line
      end
   end
   file.lines_by_function = index
   return index
end

-- Does this function body reach an execution sink? The oracle question behind a
-- whole-program run that found nothing: of the calls that crossed a file
-- boundary, how many could have reached a sink at all. It costs a walk of the
-- one function, so it is off unless `opts.whole_program_oracle` asks for it.
local function reaches_sink(file, function_node)
   for _, line in ipairs(lines_by_function(file)[function_node] or {}) do
      for _, item in ipairs(line.items) do
         if item.tag == "Eval" and type(item.node) == "table"
               and (item.node.tag == "Call" or item.node.tag == "Invoke") then
            local path = taint_engine.callee_path(item.node[1], item, taint_engine.new_state())
            if path and platform_api.match_sink(path) then return true end
         end
      end
   end
   return false
end

-- The dotted global functions of every file, by full name. A name two files
-- both define is false: binding to either would be a guess.
local function build_dotted(files)
   local dotted = {}
   for _, file in ipairs(files) do
      for name, function_node in pairs(file.dotted or {}) do
         local existing = dotted[name]
         if existing == nil then
            dotted[name] = function_node and {file = file, node = function_node} or false
         elseif existing ~= false then
            dotted[name] = false
         end
      end
   end
   return dotted
end

-- `gui.a.b.set` for a callee written as a chain of string keys off a global,
-- or nil. A root that is a local variable is not the global, so a page that
-- defines its own `gui` does not resolve through the index.
local function dotted_name(callee)
   local keys = {}
   local node = callee
   while type(node) == "table" and node.tag == "Index" do
      local key = node[2]
      if type(key) ~= "table" or key.tag ~= "String" or type(key[1]) ~= "string" then
         return nil
      end
      table.insert(keys, 1, key[1])
      node = node[1]
   end
   if type(node) ~= "table" or node.tag ~= "Id" or node.var or type(node[1]) ~= "string" then
      return nil
   end
   if #keys == 0 then return nil end
   return node[1] .. "." .. table.concat(keys, ".")
end

-- The plain global functions of every file, by name, under the same rule: a
-- name two files define is false.
local function build_globals(files)
   local globals = {}
   for _, file in ipairs(files) do
      for name, function_node in pairs(file.functions or {}) do
         local existing = globals[name]
         if existing == nil then
            globals[name] = function_node and {file = file, node = function_node} or false
         elseif existing ~= false then
            globals[name] = false
         end
      end
   end
   return globals
end

local function constant_key(node)
   return type(node) == "table" and (node.tag == "String" or node.tag == "Number")
end

-- The value a table literal gives a string key, or nil.
local function field_of(table_node, name)
   for _, item in ipairs(table_node) do
      if type(item) == "table" and item.tag == "Pair" and type(item[1]) == "table"
            and item[1].tag == "String" and item[1][1] == name then
         return item[2]
      end
   end
   return nil
end

-- `handlers[name](...)` and `routes[name].handler(...)`: a call through a table
-- literal indexed by a key known only at run time. The callee is any of the
-- table's values (or, for the second shape, the `handler` field of any of its
-- entries), so each one that names a function in another file is a target.
-- Returns the targets and whether MAX_ROUTE_TARGETS cut the list.
-- ponytail: only the literal itself is read; entries added later
-- (`routes.x.handler = f`) and handlers in the dispatcher's own file are not
-- followed. Add them when a firmware tree needs it.
local function route_targets(file, callee, index)
   if type(callee) ~= "table" or callee.tag ~= "Index" then return {} end
   local base, key, field = callee[1], callee[2], nil
   if constant_key(key) then
      if key.tag ~= "String" or type(base) ~= "table" or base.tag ~= "Index"
            or constant_key(base[2]) then
         return {}
      end
      field = key[1]
      base = base[1]
   end
   if type(base) ~= "table" or base.tag ~= "Id" then return {} end
   local literal = base.var and sole_table(file, base)
      or (not base.var and file.global_tables[base[1]]) or nil
   if not literal then return {} end

   local targets, seen, cut = {}, {}, false
   for _, item in ipairs(literal) do
      local value = type(item) == "table" and item.tag == "Pair" and item[2] or item
      if field then
         value = type(value) == "table" and value.tag == "Table" and field_of(value, field) or nil
      end
      local target
      if type(value) == "table" and value.tag == "Id" and not value.var then
         target = index.globals[value[1]]
      end
      if target and target.file ~= file and not seen[target.node] then
         if #targets >= index.max_routes then
            cut = true
            break
         end
         seen[target.node] = true
         targets[#targets + 1] = target
      end
   end
   return targets, cut
end

-- The function a dotted callee names in another file, or nil.
local function dotted_target(file, callee, index)
   local name = dotted_name(callee)
   local found = name and index.dotted and index.dotted[name]
   if not found or found.file == file then return nil end
   return found
end

-- The cross-file call sites of one file, resolved once and cached. A site is
-- {callee = file, function_node, args, item}.
local function sites_of(file, index, max_sites, oracle)
   if file.sites then return file.sites end
   file.sites = {}
   file.sites_truncated = false
   file.routes_truncated = false

   local add_target

   local function add(node, item)
      local callee = callee_of(node)
      local resolved = member_of(file, callee)
      local entry, function_node
      if resolved then
         entry = resolved.entry
            or (resolved.module and entry_for(index, resolved.module))
         if not entry or entry.file == file then return end
         function_node = function_for(entry, resolved.member)
      else
         local target = dotted_target(file, callee, index)
         if not target then
            -- A route table is reached through a call, not a method call.
            if node.tag == "Invoke" then return end
            local routed, cut = route_targets(file, callee, index)
            if cut then file.routes_truncated = true end
            for _, route in ipairs(routed) do
               add_target(node, item, {member = route.node.name or "<route>"},
                  {file = route.file, kind = "path"}, route.node)
               if file.sites_truncated then return end
            end
            return
         end
         resolved = {member = dotted_name(callee)}
         entry = {file = target.file, kind = "path"}
         function_node = target.node
      end
      add_target(node, item, resolved, entry, function_node)
   end

   add_target = function(node, item, resolved, entry, function_node)
      if not function_node then return end
      if not taint_engine.line_of_function(entry.file.chstate, function_node) then return end

      if #file.sites >= max_sites then
         file.sites_truncated = true
         return
      end

      local args = call_args(node)
      if oracle and reaches_sink(entry.file, function_node) then
         file.sites_with_sink = (file.sites_with_sink or 0) + 1
         file.sink_sites = file.sink_sites or {}
         file.sink_sites[#file.sink_sites + 1] = {
            from = file.path, line = node.line, into = entry.file.path,
            member = resolved.module or (resolved.member or "<module>"),
            match = entry.kind,
         }
      end
      file.sites[#file.sites + 1] = {
         callee = entry.file,
         function_node = function_node,
         args = args,
         item = item,
         module = resolved.module,
         module_match = entry.kind,
      }
   end

   for _, line in ipairs(file.chstate.lines) do
      for _, item in ipairs(line.items) do
         if item.tag == "Eval" and type(item.node) == "table"
               and (item.node.tag == "Call" or item.node.tag == "Invoke") then
            add(item.node, item)
            if file.sites_truncated then return file.sites end
         elseif item.tag == "Local" or item.tag == "Set" or item.tag == "OpSet" then
            -- `errorFlag, code = gui.a.b.set(t)`: the value is used, but the
            -- arguments still reach the callee's parameters.
            for _, written in ipairs(item.rhs or {}) do
               if type(written) == "table"
                     and (written.tag == "Call" or written.tag == "Invoke") then
                  add(written, item)
                  if file.sites_truncated then return file.sites end
               end
            end
         end
      end
   end

   return file.sites
end

-- ------------------------------------------------------------ taint states

-- The taint state for a file: the one the per-file pass already built when the
-- caller supplied it, otherwise one built here by the same call api makes.
--
-- `findings_mark` is the point past which anything this pass produces starts.
-- For a supplied state that is everything the per-file pass already reported, so
-- those are never reported twice.
local function state_of(file, ctx)
   if file.state_taken then return file.state end
   if not file.state then
      file.state = taint_engine.new_state()
      taint_engine.run(file.chstate, ctx.opts, file.state)
   end
   file.findings_mark = #file.state.findings
   file.state_taken = true
   return file.state
end

-- Bind a call site's arguments to the callee's formal parameters. This is the
-- interprocedural pass's own move applied across a file boundary: the
-- descriptors are computed in the caller's state and unioned into the callee's
-- parameter taint, which is the only way an argument reaches a function body.
--
-- Returns true when the callee learned something it did not already know, which
-- is what makes the fixpoint monotone: taint only ever grows, and a call site
-- that adds nothing is never re-propagated.
local function bind(caller, target, module_match, function_node, args, item, ctx)
   local state = state_of(caller, ctx)
   local target_state = state_of(target, ctx)
   local bound = false

   local vars = taint_engine.formals_of(function_node)
   for index, var in ipairs(vars) do
      local arg = args[index]
      if not arg then break end
      local arg_taint = taint_engine.of_expr(state, arg, item)
      if next(arg_taint) ~= nil then
         local existing = target_state.param_taint[var]
         if not existing then
            existing = {}
            target_state.param_taint[var] = existing
         end
         for _, descriptor in pairs(arg_taint) do
            -- Where the untrusted data first appeared, keyed by the descriptor
            -- itself rather than by its id: two files reading the same source
            -- API produce two descriptors with the same id, and only the object
            -- tells them apart. The first file to pass one on is the file it was
            -- created in, because a descriptor can only be in another file's
            -- state if an earlier binding put it there.
            if not ctx.origin[descriptor] then ctx.origin[descriptor] = caller.path end
            if not existing[descriptor.id] then
               existing[descriptor.id] = descriptor
               bound = true
            end
         end
      end
   end

   -- The file this one took its taint from, recorded once. Walking that back one
   -- hop at a time gives the whole path a flow crossed, without a separate
   -- chain per finding to keep consistent.
   if bound then
      if not target.entry_path then target.entry_path = caller.path end
      target.module_match = weaker_match(target.module_match, module_match)
   end

   return bound
end

-- The files a finding's flow passed through, sink first. Each file remembers the
-- file its taint arrived from, so the walk back needs no search and no cycle
-- guard beyond a bound.
local function chain_for(file, ctx)
   local chain = {file}
   local seen = {[file] = true}
   local current = file
   for _ = 1, MAX_CHAIN do
      local next_file = current.entry_path and ctx.files_by_path[current.entry_path]
      if not next_file or seen[next_file] then break end
      chain[#chain + 1] = next_file
      seen[next_file] = true
      current = next_file
   end
   return chain
end

-- ------------------------------------------------------------ findings

-- Attach what a whole-program flow adds to a finding: the file it is in, a trace
-- whose every step names its file, the files the flow crossed, and an honest
-- note when one of them was only analyzed approximately.
local function annotate(finding, file, ctx)
   finding.file = file.path

   local chain = chain_for(file, ctx)
   local sources = finding.sources
   local trace = {}
   local from = chain[#chain] and chain[#chain].path

   if type(sources) == "table" and #sources > 0 then
      for _, descriptor in ipairs(sources) do
         local source_file = ctx.origin[descriptor]
         if source_file then from = source_file end
         trace[#trace + 1] = {
            kind = "source",
            name = descriptor.display_id or descriptor.id,
            line = descriptor.line,
            file = source_file or file.path,
         }
      end
      trace[#trace + 1] = {
         kind = "sink", name = finding.sink, line = finding.line, file = file.path,
      }
      finding.trace = trace
   end
   local crossed, approximate, paths = false, {}, {}
   for _, hop in ipairs(chain) do
      paths[#paths + 1] = hop.path
      if hop ~= file then crossed = true end
      if hop.approximate then approximate[#approximate + 1] = hop.path end
   end

   -- A flow that crossed a required module's return names that module's file.
   if ctx.via and type(sources) == "table" then
      for _, descriptor in ipairs(sources) do
         local via = ctx.via[descriptor.id]
         if via then
            local seen = false
            for _, p in ipairs(paths) do if p == via then seen = true end end
            if not seen then paths[#paths + 1] = via end
         end
      end
   end

   local notes = {}
   if crossed and from then
      notes[#notes + 1] = "untrusted data reached this sink from " .. from
   end
   if #approximate > 0 then
      -- Never present a flow that leans on a file we only analyzed
      -- approximately as a proven one: say which file and drop a confidence
      -- step, because the finding may be wrong in the direction of a false
      -- positive or a false negative.
      notes[#notes + 1] = "reduced precision: " .. table.concat(approximate, ", ")
         .. " was analyzed approximately"
      finding.confidence = weaken(finding.confidence)
   end
   if is_inference(file.module_match) then
      notes[#notes + 1] = "the module was matched by name rather than by its path"
   end
   if ctx.bounds then
      for _, bound in ipairs(ctx.bounds) do
         notes[#notes + 1] = "whole-program analysis stopped at its "
            .. bound.bound .. " bound, so this flow may be incomplete"
      end
   end

   if #notes > 0 then
      finding.message = finding.message .. "; " .. table.concat(notes, "; ")
   end

   finding.whole_program = {
      from = from or file.path,
      into = file.path,
      files = paths,
      approximate = approximate,
      module_match = file.module_match or "path",
   }
   if ctx.bounds then
      finding.whole_program.bounds_hit = {}
      for index, bound in ipairs(ctx.bounds) do
         finding.whole_program.bounds_hit[index] = bound.bound
      end
   end

   return finding
end

-- ------------------------------------------------------------ driver

--- Analyze a set of files as one program.
--
-- `states` is an array of `{path = <string>, chstate = <luacheck check state>,
-- state = <optional taint state>}`, one per file: what a per-file run has
-- already built. A file that could not be parsed, or whose chstate is nil, is
-- skipped.
--
-- Options are the taint engine's own (`sources`, `source_confidence`, ...), plus:
--
--   max_function_lines              the budget api uses to decide a file is too
--                                   large for cross-function analysis; a file
--                                   over it counts as analyzed approximately
--   whole_program_basename          also resolve a name to the one scanned file
--                                   with that basename (default false)
--   whole_program_max_rounds        fixpoint rounds (default 8)
--   whole_program_max_modules       distinct callee files one file may feed
--                                   (default 32)
--   whole_program_max_sites         cross-file call sites considered per file
--                                   (default 4096)
--   whole_program_oracle            also list the cross-file calls that reach a
--                                   sink, which is what a run that found nothing
--                                   needs to be judged by (default false)
--
-- Returns the findings the whole-program pass produced, each carrying `file`, a
-- per-step trace, and a `whole_program` block naming the files the flow crossed,
-- and a diagnostics table describing the run: files and modules indexed, names
-- left ambiguous, work done, and every bound hit. The findings are only the ones
-- this pass caused; the per-file findings are the caller's to merge.
function whole_program.analyze(states, opts)
   opts = opts or {}

   local ctx = {
      opts = opts,
      -- Weak keys: the descriptors are held by the taint states that created
      -- them, and this map only has to answer "which file was this one first
      -- seen in" while the run lasts.
      origin = setmetatable({}, {__mode = "k"}),
      files_by_path = {},
   }
   local diagnostics = {
      files = 0, modules = 0, ambiguous_modules = 0, cross_file_sites = 0,
      propagations = 0, rounds = 0, findings = 0, bounds_hit = {},
      -- Work done, so a regression toward a quadratic walk is visible as a
      -- number rather than only as a slower run. Both grow linearly in the
      -- number of files: the index visits every item once, and a call site is
      -- checked at most once per round.
      items_scanned = 0, site_checks = 0, sites_with_sink = 0, sink_sites = {},
   }

   -- Set when the oracle asks for it: the calls that crossed a file boundary and
   -- reached a sink, which is the population a whole-program run could report
   -- from. An empty list with `cross_file_sites` non-empty is the honest answer
   -- for a tree where no boundary leads to anything dangerous.
   local function record_sink_sites(file)
      for _, site in ipairs(file.sink_sites or {}) do
         diagnostics.sink_sites[#diagnostics.sink_sites + 1] = site
      end
   end

   local function note_bound(name, file_path)
      for _, bound in ipairs(diagnostics.bounds_hit) do
         if bound.bound == name then return end
      end
      diagnostics.bounds_hit[#diagnostics.bounds_hit + 1] = {bound = name, file = file_path}
   end

   local files = {}
   for _, entry in ipairs(states or {}) do
      if type(entry) == "table" and type(entry.path) == "string"
            and type(entry.chstate) == "table" then
         local file = {
            path = entry.path,
            chstate = entry.chstate,
            state = entry.state,
            binds = {},
            -- A file flow-sensitive dataflow was skipped for, or that is too
            -- large for cross-function analysis, cannot support a proven
            -- cross-file claim.
            approximate = entry.chstate.resolved_locals == false
               or #entry.chstate.lines > (opts.max_function_lines or 4000),
         }
         ctx.files_by_path[file.path] = file
         files[#files + 1] = scan(file)
      end
   end
   diagnostics.files = #files
   for _, file in ipairs(files) do
      diagnostics.items_scanned = diagnostics.items_scanned + (file.items_scanned or 0)
   end
   if #files < 2 then return {}, diagnostics end

   local index = build_index(files, opts)
   index.dotted = build_dotted(files)
   index.globals = build_globals(files)
   index.max_routes = bound_of(opts, "whole_program_max_route_targets")
   diagnostics.modules = count(index.modules)
   diagnostics.ambiguous_modules = count(index.ambiguous)
   for _, file in ipairs(files) do
      resolve_binds(file, index)
   end

   local max_rounds = bound_of(opts, "whole_program_max_rounds")
   local max_modules = bound_of(opts, "whole_program_max_modules")
   local max_sites = bound_of(opts, "whole_program_max_sites")

   local findings = {}
   local rounds = 0
   local queue = {}
   local queued = {}
   for _, file in ipairs(files) do
      queue[#queue + 1] = file
      queued[file] = true
   end

   -- Findings are collected as they appear and annotated once the run is over,
   -- so a bound hit in the last round annotates every finding the run produced
   -- rather than only the ones after it.
   local pending = {}

   -- A call whose value is used - os.execute(m.id(x)), local v = m.id(x) - is
   -- not a statement, so sites_of never sees it and bind never runs. The taint
   -- engine asks for such a callee through state.resolve_external, and follows
   -- the target function's return in the target file's own state. Every file
   -- gets its state first, so no taint run starts inside another file's
   -- propagation. Only a variable bound to a required module is resolved; a
   -- require() called inline inside an expression is not.
   local hooked = {}
   for _, file in ipairs(files) do
      if next(file.modules_of_var or {}) then hooked[#hooked + 1] = file end
   end
   if #hooked > 0 then
      for _, file in ipairs(files) do state_of(file, ctx) end
      for _, file in ipairs(hooked) do
         local memo = {}
         file.state.resolve_external = function(call_node)
            local cached = memo[call_node]
            if cached == nil then
               cached = false
               local resolved = member_of(file, callee_of(call_node))
               local entry = resolved and (resolved.entry or entry_for(index, resolved.module))
               local fn = entry and entry.file ~= file and function_for(entry, resolved.member)
               if fn then cached = {fn, state_of(entry.file, ctx), entry.file.path} end
               memo[call_node] = cached
            end
            if cached then return cached[1], cached[2], cached[3] end
            return nil
         end
         file.state.on_external_return = function(returned, arg_taints, target_path)
            local from_caller = {}
            for _, set in ipairs(arg_taints) do
               for id in pairs(set) do from_caller[id] = true end
            end
            ctx.via = ctx.via or {}
            for id, descriptor in pairs(returned) do
               if from_caller[id] then
                  ctx.via[id] = ctx.via[id] or target_path
               elseif not ctx.origin[descriptor] then
                  ctx.origin[descriptor] = target_path
               end
            end
         end
         taint_engine.run(file.chstate, opts, file.state)
         diagnostics.propagations = diagnostics.propagations + 1
         for i = file.findings_mark + 1, #file.state.findings do
            pending[#pending + 1] = {finding = file.state.findings[i], file = file}
         end
         file.findings_mark = #file.state.findings
      end
   end

   while #queue > 0 and rounds < max_rounds do
      rounds = rounds + 1
      local batch = queue
      queue = {}
      queued = {}

      -- Everything that received taint in this round is re-propagated once, and
      -- only once: a file's own propagation converges on its own, so re-running
      -- it per call site would be the quadratic shape this avoids.
      local to_propagate, propagating = {}, {}

      for _, file in ipairs(batch) do
         local sites = sites_of(file, index, max_sites, opts.whole_program_oracle)
         if file.sites_truncated then note_bound("call sites", file.path) end
         if file.routes_truncated then note_bound("route table targets", file.path) end

         file.modules_bound = file.modules_bound or {}
         for _, site in ipairs(sites) do
            diagnostics.site_checks = diagnostics.site_checks + 1
            if bind(file, site.callee, site.module_match, site.function_node,
                     site.args, site.item, ctx) then
               if not propagating[site.callee] then
                  propagating[site.callee] = true
                  to_propagate[#to_propagate + 1] = site.callee
               end
               if not file.modules_bound[site.callee] then
                  if count(file.modules_bound) >= max_modules then
                     note_bound("modules per file", file.path)
                     break
                  end
                  file.modules_bound[site.callee] = true
               end
            end
         end
      end

      for _, file in ipairs(to_propagate) do
         taint_engine.run(file.chstate, opts, file.state)
         diagnostics.propagations = diagnostics.propagations + 1
         for index = file.findings_mark + 1, #file.state.findings do
            pending[#pending + 1] = {finding = file.state.findings[index], file = file}
         end
         file.findings_mark = #file.state.findings
         if not queued[file] then
            queued[file] = true
            queue[#queue + 1] = file
         end
      end
   end
   diagnostics.rounds = rounds

   if #queue > 0 then
      note_bound("fixpoint rounds", queue[1].path)
   end

   ctx.bounds = diagnostics.bounds_hit
   for _, entry in ipairs(pending) do
      findings[#findings + 1] = annotate(entry.finding, entry.file, ctx)
   end

   for _, file in ipairs(files) do
      if file.sites then
         diagnostics.cross_file_sites = diagnostics.cross_file_sites + #file.sites
         if file.sites_with_sink then
            diagnostics.sites_with_sink = diagnostics.sites_with_sink + file.sites_with_sink
         end
         record_sink_sites(file)
      end
   end
   diagnostics.findings = #findings

   return findings, diagnostics
end

return whole_program
