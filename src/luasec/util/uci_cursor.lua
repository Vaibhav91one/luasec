-- Which calls are writes through a UCI cursor handle.
--
-- `uci.cursor()`, a function that returns one, and the names and fields that
-- hold one are followed here so that two layers can ask the same question: the
-- credential rule (747, rules/secrets.lua) and the dataflow pass (722,
-- engine/taint.lua). The tracking is per file and bounded; see the notes on
-- each cap below.
local context = require "luasec.rules.context"

local M = {}

-- The string value of a node, or nil when it is not a string literal.
-- A secret split across concatenations at author time is still a literal in the
-- binary: `local key = "AAAA" .. "BBBB"` is one constant. Fold String and Concat
-- into the value the program will actually hold. The depth cap keeps a crafted
-- file proportional to its size.
local MAX_CONSTANT_CONCAT_DEPTH = 8

local function string_value(node, depth)
   if type(node) ~= "table" then return nil end
   if node.tag == "String" and type(node[1]) == "string" then
      return node[1]
   end
   depth = depth or 0
   -- luacheck spells concatenation as an `Op` node whose slot 1 is the operator
   -- name, so the operands are slots 2 and 3.
   if node.tag ~= "Op" or node[1] ~= "concat" or depth > MAX_CONSTANT_CONCAT_DEPTH then
      return nil
   end
   local left = string_value(node[2], depth + 1)
   local right = string_value(node[3], depth + 1)
   if not left or not right then return nil end
   return left .. right
end

-- The called function's name, however this parser spells the two call forms:
-- `Call` puts the name at [1] for a.b:c(...) and the receiver at [2] for a:b(...).
local function called_name(node)
   if type(node) ~= "table" then return "" end
   -- `a:b(...)` is an Invoke: slot 1 is the object, slot 2 the method name.
   if node.tag == "Invoke" then return string_value(node[2]) or "" end
   local callee = node[1]
   if type(callee) ~= "table" then return "" end
   -- `a.b(...)` is a Call whose callee is an Index: the name is the base, a dot
   -- and the field.
   if callee.tag == "Index" then
      local base = type(callee[1]) == "table" and callee[1][1] or nil
      local field = string_value(callee[2])
      if type(base) == "string" and field then return base .. "." .. field end
      return field or ""
   end
   if callee.tag == "Id" and type(callee[1]) == "string" then return callee[1] end
   return ""
end

-- Config writers, by the name the call actually carries. This is the set the
-- OpenWrt profile declares, not a guess: a suffix match on `set` fires on
-- `m.set`, `db:set` and every other method that happens to be called set, and
-- `t:set("password", "...")` on an ordinary table is not a config write.
local CONFIG_WRITER_CALLS = {
   ["uci.set"] = true, ["uci.add"] = true, ["uci.sets"] = true,
}

local CONFIG_WRITE_METHODS = {set = true, add = true, setlist = true}

-- `uci.cursor()` and the cursors it returns, so `cursor:set(k, v)` is read as a
-- config write and `db:set(k, v)` is not.
--
-- Matched on the method name plus a cursor-ish factory, not on the receiver's
-- name: firmware aliases the module, so `muci.cursor()` and `uci.cursor()` are
-- the same object written two ways, and `luci.cursor` appears in more of the
-- corpus than the bare spelling. Matching the factory's last identifier is what
-- makes those two spellings agree.
-- Values assigned to table fields we can see, keyed "base.field" where base is
-- the name of the table. Built once per file, before any rule asks about a
-- cursor, because a call can appear before the assignment that defines it.
-- Per table field, what this file ever assigned to it: whether a handle, and
-- whether anything at all. See the pre-pass below.
local FIELD_VALUES = {}

local function field_key(node, field)
   if type(node) ~= "table" or node.tag ~= "Id" then return nil end
   local name = node[1]
   -- `field` is a String node's value, but this is also reached from paths
   -- where it is a node, and concatenating a table raises.
   if type(name) ~= "string" or type(field) ~= "string" then return nil end
   return name .. "." .. field
end

-- The summary for `base.field`, or nil when this file says nothing about it.
local function field_record(base, field)
   local key = field_key(base, field)
   if not key then return nil end
   return FIELD_VALUES[key]
end

-- The `uci` module, however it is reached: a local named for it, a global, or
-- a `require("uci")` the AST still shows us.
-- A receiver reached through a field or a global, so `self.uci:set(...)` and a
-- module-level `cursor` are followed as well as a local binding.
local MAX_CURSOR_HOPS = 6

-- How many reaching definitions of ONE local are followed.
--
-- The hop limit bounds the DEPTH of this walk, not its branching factor: every
-- Id reached is followed to each of its definitions, so a local reassigned N
-- times multiplies the work by N at each hop and the whole thing is
-- O(branches^depth). That was free while this ran once per USE of a field, and
-- it stopped being free when the answer moved into a pre-pass that runs once
-- per field ASSIGNMENT: a 369-line file with 60 reassignments chained through
-- five aliases did not finish in 300 s, and an ordinary 40,000-line module with
-- one heavily-reassigned local and 20,000 fields took 28 s where it had taken
-- 1.2 s. --max-nodes does not help, because `var.values` is filled by the parser
-- and exists even when resolve_locals was skipped.
--
-- Bounded here, newest definitions first, because the definition nearest the
-- use is the one that decides it.
local MAX_CURSOR_DEFS = 4

-- One answer per node, per file. The same local is reached from many fields and
-- the answer cannot differ between them.
local CURSOR_MEMO = {}

-- Functions this file defines, by the spelling a call reaches them with: `open`
-- for a global `function open()`, `M.open` for `function M.open()` or
-- `M.open = function`. Built in the same pre-pass as FIELD_VALUES. A name given
-- two different functions is dropped, so a call never follows a guess.
local FUNCTIONS = {}

-- A function's `return` expressions, not those of functions nested in it.
-- RETURNS_MEMO holds the answer per Function node for the file; the list is cut
-- at MAX_CURSOR_DEFS so a function with a hundred returns costs what four do.
local RETURNS_MEMO = {}

local function return_exprs(function_node)
   local memo = RETURNS_MEMO[function_node]
   if memo then return memo end
   local found = {}
   local function walk(node, depth)
      if type(node) ~= "table" or depth > 64 or #found >= MAX_CURSOR_DEFS then return end
      if node.tag == "Function" and node ~= function_node then return end
      if node.tag == "Return" then
         for _, expr in ipairs(node) do
            if #found < MAX_CURSOR_DEFS then found[#found + 1] = expr end
         end
         return
      end
      for _, child in ipairs(node) do walk(child, depth + 1) end
   end
   walk(function_node, 0)
   RETURNS_MEMO[function_node] = found
   return found
end

local function is_uci_module(node, depth)
   if type(node) ~= "table" or (depth or 0) > MAX_CURSOR_HOPS then return false end
   if node.tag == "Invoke" or node.tag == "Call" then
      if called_name(node) == "require" then
         local first = node.tag == "Invoke" and node[3] or node[2]
         -- `luci.model.uci` is the canonical LuCI path and `uci` the bare one;
         -- a module path is uci's when uci is a whole segment of it, or the
         -- whole of it. Substring matching would take `luci.sys` and `cusick`
         -- for a cursor.
         local module = string_value(first)
         if module == nil then return false end
         if module == "uci" or module == "muci" then return true end
         for segment in module:gmatch("[^%.]+") do
            if segment == "uci" or segment == "muci" then return true end
         end
         return false
      end
      return is_uci_module(node[1], (depth or 0) + 1)
   end
   if node.tag == "Id" then
      local name = type(node[1]) == "string" and node[1] or ""
      if string.find(name, "uci", 1, true) then return true end
      if node.var then
         for _, value in ipairs(node.var.values or {}) do
            if value.node and is_uci_module(value.node, (depth or 0) + 1) then
               return true
            end
         end
      end
   end
   return false
end

-- The Function node a call's callee names in this file, or nil: a local
-- (its reaching definitions, newest first), a global, or a `M.name` field.
local function function_of(callee)
   if callee.tag == "Id" then
      if callee.var then
         local values = callee.var.values or {}
         for index = #values, math.max(1, #values - MAX_CURSOR_DEFS + 1), -1 do
            local value = values[index]
            if value and value.node and value.node.tag == "Function" then return value.node end
         end
         return nil
      end
      return FUNCTIONS[callee[1]] or nil
   end
   if callee.tag == "Index" then
      local key = field_key(callee[1], string_value(callee[2]))
      return key and FUNCTIONS[key] or nil
   end
   return nil
end

local is_cursor

is_cursor = function(node, depth)
   if type(node) ~= "table" then return false end
   depth = depth or 0
   if depth > MAX_CURSOR_HOPS then return false end

   local memo = CURSOR_MEMO[node]
   if memo ~= nil then return memo end

   if node.tag == "Call" or node.tag == "Invoke" then
      -- Three ways firmware makes a cursor, and the spelling is not fixed:
      -- `uci.cursor()` and `muci.cursor()` name the module, a bare `cursor()`
      -- needs no name, and firmware wraps it in its own helper
      -- (`local c = mkcursor()`), which has no module to name either.
      --
      -- A named module that is NOT uci is rejected, so a library's own
      -- `sqlite.cursor()` is not a config write. Requiring "uci" in the name
      -- would have been tidier, but `mkcursor` has nothing in it.
      local name = called_name(node)
      if name == "" then return false end
      if string.find(name, "uci", 1, true) then return true end
      local callee = node[1]
      -- A factory this file defines is decided by what it returns, not by what
      -- it is called: `open_section()` that ends in `return uci.cursor()` hands
      -- back a handle, and `sqlite.cursor()` wrapped the same way does not (#317).
      -- A handle on any return path is a handle, as for a field above. The memo
      -- is set before the walk so a factory that returns its own call settles
      -- on false instead of recursing.
      local function_node = type(callee) == "table" and function_of(callee)
      if function_node then
         CURSOR_MEMO[node] = false
         for _, expr in ipairs(return_exprs(function_node)) do
            if is_cursor(expr, depth + 1) then
               CURSOR_MEMO[node] = true
               return true
            end
         end
      end
      if type(callee) == "table" and callee.tag == "Index" then
         -- A module access, so the module is the base: `require("uci").cursor()`
         -- is the documented way to get one, and `sqlite.cursor()` is a
         -- different library's object that happens to share the field name.
         return is_uci_module(callee[1], depth + 1)
      end
      -- `mkcursor()` is a bare call: firmware's own helper, with no module
      -- behind it to rule out.
      return string.find(name, "cursor$") ~= nil
   end

   -- `self.uci` and `m.uci`: the field of a table that was built somewhere we
   -- can see. The field name carries the signal; the value is only followed so
   -- an alias of an alias still resolves.
   if node.tag == "Index" then
      -- Anchored at both ends on purpose. `^u?ci` alone matched cipher, cidr,
      -- citation, cities and circuit, which are ordinary identifiers in
      -- firmware code, and reported each one's :set as a config write. A field
      -- is a cursor when it is named like one, wholly.
      local field = string_value(node[2])
      if field == "uci" or field == "_uci" or field == "muci" or field == "cursor" then
         local record = field_record(node[1], field)
         -- Nothing assigned here that this file can see: `self.uci` is set by a
         -- constructor in another file, and the name is all there is.
         if record == nil then return true end
         -- Assigned here: a handle was, or nothing was. `t.uci = true` is not a
         -- config cursor, and a field assigned a handle and then a boolean on
         -- another path is a handle, because which way the program went decides.
         if record.handle then return true end
         if record.assigned then return false end
         return true
      end
      return is_cursor(node[1], depth + 1)
   end

   if node.tag == "Id" then
      -- A binding we can see is decided by what it is bound to. A local called
      -- `mycursor` holding a plain table is a plain table: reading its name
      -- instead of its definition reported every helper table whose author
      -- happened to end the name with cursor.
      if node.var then
         local values = node.var.values or {}
         for index = #values, math.max(1, #values - MAX_CURSOR_DEFS + 1), -1 do
            local value = values[index]
            if value and value.node and is_cursor(value.node, depth + 1) then
               CURSOR_MEMO[node] = true
               return true
            end
         end
         CURSOR_MEMO[node] = false
         return false
      end
      -- A global has no reaching definitions, so its name is all there is.
      local name = type(node[1]) == "string" and node[1] or ""
      return name == "uci" or name == "_uci" or name == "muci" or name == "cursor"
   end

   return false
end

local function config_writer(node)
   if node.tag == "Invoke" then
      return CONFIG_WRITE_METHODS[string_value(node[2]) or ""] == true
         and is_cursor(node[1])
   end
   -- `cur.set(...)` and `uci.set(...)` are the same write; a Call reaches a
   -- cursor the same way an Invoke does.
   if CONFIG_WRITER_CALLS[called_name(node)] then return true end
   local name = called_name(node)
   local tail = name:match("([%w_]+)$")
   if tail == nil or not CONFIG_WRITE_METHODS[tail] then return false end
   return is_cursor(node[1])
end

-- Build the per-file state for `ast` and make it the one the questions below
-- are answered from. Cheap to call again for a file already prepared: the
-- engine walks several files in turn, and each question must be answered from
-- its own file's table fields and functions.
local prepared = setmetatable({}, {__mode = "k"})

function M.prepare(ast)
   local state = prepared[ast]
   if state then
      FIELD_VALUES, CURSOR_MEMO, FUNCTIONS, RETURNS_MEMO = state[1], state[2], state[3], state[4]
      return
   end
   FIELD_VALUES, CURSOR_MEMO, FUNCTIONS, RETURNS_MEMO = {}, {}, {}, {}
   prepared[ast] = {FIELD_VALUES, CURSOR_MEMO, FUNCTIONS, RETURNS_MEMO}
   local function each_node(visit) context.walk(ast, visit) end
-- First pass: what is assigned to each table field. A call can appear
   -- before the assignment that defines it, so this is collected before any
   -- rule asks whether something is a config cursor.
   -- Functions first, in a pass of their own: a factory can be defined below
   -- the assignment that calls it, and is_cursor reads this table.
   each_node(function(node)
      if node.tag == "Set" or node.tag == "Local" then
         local targets, values = node[1], node[2]
         if type(targets) == "table" and type(values) == "table" then
            for index, target in ipairs(targets) do
               local defined = values[index]
               if type(target) == "table" and type(defined) == "table"
                     and defined.tag == "Function" then
                  local key = target.tag == "Id" and not target.var and type(target[1]) == "string"
                     and target[1]
                     or (target.tag == "Index" and field_key(target[1], string_value(target[2])))
                  if key then
                     if FUNCTIONS[key] == nil then
                        FUNCTIONS[key] = defined
                     elseif FUNCTIONS[key] ~= defined then
                        FUNCTIONS[key] = false
                     end
                  end
               end
            end
         end
      end
   end)
   each_node(function(node)
      if node.tag == "Set" or node.tag == "OpSet" or node.tag == "Local" then
         local targets, values = node[1], node[2]
         if type(targets) == "table" and type(values) == "table" then
            for index, target in ipairs(targets) do
               if type(target) == "table" and target.tag == "Index" then
                  local key = field_key(target[1], string_value(target[2]))
                  if key then
                     -- `local t = {} ; t.a, t.b = 1` has two targets and one
                     -- value, so values[2] is nil. `(value == nil) and false or
                     -- value.tag` evaluates the right operand anyway, indexed nil,
                     -- and raised inside the rule: every secrets finding in the
                     -- file was replaced by "a rule failed to run". It fires on
                     -- four files in the corpus, on an idiom that is everywhere.
                     local value = values[index]
                     if type(value) == "table" then
                        -- Summarised to a fact, not kept as a list. The list was
                        -- quadratic: the answer is asked once per use of the field
                        -- and the uses are once per line, so 32,000 assignments
                        -- with 32,000 uses took 109 s where the earlier build took
                        -- 5 s.
                        --
                        -- Capping the list fixed the time and cost a finding, which
                        -- is the one direction this tool may not fail in: a cursor
                        -- assigned as the ninth value to a field was invisible,
                        -- and a hardcoded credential written through it went
                        -- unreported. A cap is positional. This boolean answers
                        -- the actual question - was a handle ever assigned here -
                        -- in O(1) per assignment and O(1) per use, and cannot
                        -- lose the ninth cursor.
                        --
                        -- Asked with `is_cursor` and not with a test for whether
                        -- the value is a call. A test for the tag answers a
                        -- DIFFERENT question, and it was wrong in both
                        -- directions: six shapes that store a cursor rather than
                        -- call one went dark at every position
                        -- (`local c = uci.cursor(); M.uci = c`, an alias chain,
                        -- `self.cursor`, an uncalled `uci.cursor`, a global
                        -- `cursor`, `t2.uci`) while `f()`, `t.setup()`,
                        -- `db:query()` and `setmetatable({}, {})` all became
                        -- config writes, including another library's
                        -- `store.cursor`. A hardcoded root password written
                        -- through a stored cursor went unreported, which is the
                        -- one direction this may not fail in.
                        --
                        -- Nothing caught it: the corpus's 747 count is 0 whatever
                        -- this rule does, and no fixture assigned a non-call
                        -- cursor to a field. 568 specs and a 146-finding corpus
                        -- measurement all agreed with the broken rule.
                        --
                        -- The walk behind `is_cursor` is bounded in depth AND in
                        -- fan-out, because a pre-pass call costs one branch per
                        -- reaching definition per hop: unbounded, a 369-line file
                        -- did not finish in 300 s and an ordinary 40,000-line
                        -- module took 28 s where it had taken 1.2 s.
                        local record = FIELD_VALUES[key] or {handle = false, assigned = false}
                        record.assigned = true
                        if is_cursor(value, 0) then record.handle = true end
                        FIELD_VALUES[key] = record
                     end
                  end
               end
            end
         end
      end
   end)
end

M.string_value = string_value
M.called_name = called_name
M.config_writer = config_writer

-- The methods of a cursor that change configuration, for the dataflow pass.
-- A wider set than 747 reads: `section` and `tset` create or fill a section
-- from a table, `add_list` appends to a list option.
local WRITE_METHODS = {set = true, add = true, setlist = true, section = true,
                       tset = true, add_list = true, set_list = true}

-- Is this Invoke a write through a cursor handle (`c:set(...)`)?
function M.cursor_write(node)
   if node.tag ~= "Invoke" then return false end
   return WRITE_METHODS[string_value(node[2]) or ""] == true and is_cursor(node[1])
end

return M
