-- Shared machinery for rule modules.
--
-- A detector is a function(ctx) that calls ctx:emit(code, node, extra). The
-- context owns traversal, positions, snippets and finding construction, so a
-- detector is a statement about Lua, not about AST plumbing.
local codes = require "luasec.rules.codes"
local util = require "luasec.util.util"
local const_eval = require "luasec.util.const_eval"

local context = {}
local Context = util.__index and nil or nil

local M = {}
M.__index = M

-- ------------------------------------------------------------- traversal

-- Depth-first over every expression node, parents before children.
local function walk(node, visit, depth)
   depth = depth or 0
   if depth > 200 or type(node) ~= "table" then return end
   visit(node)
   for index = 1, #node do
      local child = node[index]
      if type(child) == "table" then
         if child.tag then
            walk(child, visit, depth + 1)
         else
            for _, sub in ipairs(child) do
               if type(sub) == "table" and sub.tag then
                  walk(sub, visit, depth + 1)
               end
            end
         end
      end
   end
end

function M.new(chstate, source, opts)
   local self = setmetatable({
      chstate = chstate,
      source = source,
      opts = opts or {},
      findings = {},
   }, M)
   return self
end

--- Call `visit(node)` for every expression node in the file.
function M:each_node(visit)
   walk(self.chstate.ast, visit)
end

--- Call `visit(node, path)` for every call, with the callee's dotted path when
-- it can be resolved from a literal base.
function M:each_call(visit)
   self:each_node(function(node)
      if node.tag == "Call" or node.tag == "Invoke" then
         visit(node, self:path_of(node[1]))
      end
   end)
end

--- Every string literal in the file, in source order.
function M:each_string(visit)
   local literals = {}
   self:each_node(function(node)
      if node.tag == "String" then literals[#literals + 1] = node end
   end)
   table.sort(literals, function(a, b) return a.offset < b.offset end)
   for _, node in ipairs(literals) do visit(node, node[1]) end
end

--- Dotted path of an expression, following literal field access only.
function M:path_of(node)
   if type(node) ~= "table" then return nil end
   if node.tag == "Id" and not node.var then return node[1] end
   if node.tag == "Index" and node[2] and node[2].tag == "String" then
      local base = self:path_of(node[1])
      if base then return base .. "." .. node[2][1] end
   end
   return nil
end

--- Arguments of a call expression, as node list.
function M.args_of(node)
   local args = {}
   if node.tag == "Call" then
      for index = 2, #node do args[#args + 1] = node[index] end
   elseif node.tag == "Invoke" then
      for index = 3, #node do args[#args + 1] = node[index] end
   end
   return args
end

--- The value of a string literal at a node, or nil.
function M.literal(node)
   if type(node) == "table" and node.tag == "String" then return node[1] end
   return nil
end

--- Folded constant value of an expression, or nil.
function M.constant(node)
   return const_eval.value(node)
end

function M.is_constant(node)
   return const_eval.is_constant(node)
end

--- Source text of a node, whitespace collapsed.
function M:snippet(node)
   if not self.source or not node then return nil end
   local from = math.max(1, node.offset)
   local to = math.min(#self.source, node.end_offset)
   if to <= from then return nil end
   return (self.source:sub(from, to):gsub("%s+", " "))
end

--- Line and column of a node, as luacheck reports them.
function M:position(node)
   local line = node.line or 1
   local column = node.offset - (self.chstate.line_offsets[line] or 0) + 1
   local line_length = self.chstate.line_lengths[line]
   if line_length then
      column = math.max(1, math.min(line_length, column))
   end
   local end_column = column + math.max(0, (node.end_offset or node.offset) - node.offset)
   return line, column, end_column
end

--- Emit a finding. `code` must be registered; `name` is the matched API or value.
function M:emit(code, node, extra)
   local spec = codes.get(code)
   if not spec then
      error("rule emitted unregistered code " .. tostring(code), 0)
   end
   extra = extra or {}
   local line, column, end_column = self:position(node)

   local finding = {
      code = code,
      line = line,
      column = column,
      end_column = end_column,
      severity = extra.severity or spec.severity,
      confidence = extra.confidence or spec.confidence or "medium",
      cwe = spec.cwe,
      name = extra.name or "<rule>",
      sink = extra.sink,
      source = extra.source,
   }

   for key, value in pairs(extra) do
      if key ~= "severity" and key ~= "confidence" then
         finding[key] = value
      end
   end

   finding.message = codes.render(spec, finding)
   self.findings[#self.findings + 1] = finding
   return finding
end

return M
