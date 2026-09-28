-- Builds a luacheck check state for one source file: decode, parse, then the
-- linearize + name_functions stages that give us a control flow graph, and
-- resolve_locals, which gives flow-sensitive reaching definitions.
--
-- We deliberately do not run luacheck's lint stages; we only want its front end
-- and its dataflow.
--
-- Cost note: resolve_locals walks a linearized line once per variable defined in
-- it, so its cost grows quadratically with the number of statements in a single
-- scope. A generated file with 16,000 sequential locals takes 23 seconds there.
-- Above `max_nodes` we therefore skip it and say so, rather than hang: the
-- analysis degrades to a single forward pass and reports 904.
local decoder = require "luacheck.decoder"
local parser = require "luacheck.parser"
local check_state = require "luacheck.check_state"
local unwrap_parens = require "luacheck.stages.unwrap_parens"
local linearize = require "luacheck.stages.linearize"
local name_functions = require "luacheck.stages.name_functions"
local resolve_locals = require "luacheck.stages.resolve_locals"
local utils = require "luacheck.utils"

local parse_context = {}

-- Count expression nodes, giving up once the budget is spent so a pathological
-- input cannot make the counter itself expensive.
local function count_nodes(node, budget)
   if budget <= 0 or type(node) ~= "table" then return budget end
   budget = budget - 1
   for index = 1, #node do
      local child = node[index]
      if type(child) == "table" then
         if child.tag then
            budget = count_nodes(child, budget)
         else
            for _, sub in ipairs(child) do
               if type(sub) == "table" and sub.tag then
                  budget = count_nodes(sub, budget)
               end
            end
         end
      end
      if budget <= 0 then return 0 end
   end
   return budget
end

--- Build a check state.
-- Returns chstate, or nil plus a syntax error.
-- Options:
--   max_nodes   skip flow-sensitive dataflow above this node count (default 20000)
-- A UTF-8 byte order mark is three bytes of encoding metadata, not source. Lua
-- does not allow it at the start of a chunk, so a file that opens with one fails
-- to parse - and this pipeline reports that as 901, "could not be parsed", for a
-- file a Lua 5.4 interpreter would load. Firmware files edited on Windows carry
-- one often enough to matter.
--
-- Stripped here, before the lexer, rather than after: the lexer derives the line
-- offsets every finding is located with, so removing three bytes later would put
-- every column on line 1 out by three.
local UTF8_BOM = string.char(239, 187, 191)

local function strip_bom(bytes)
   if type(bytes) == "string" and bytes:sub(1, 3) == UTF8_BOM then
      return bytes:sub(4)
   end
   return bytes
end

function parse_context.build(source_bytes, options)
   options = options or {}
   local max_nodes = options.max_nodes or 20000
   source_bytes = strip_bom(source_bytes)

   local chstate = check_state.new(source_bytes)
   chstate.source = decoder.decode(source_bytes)
   chstate.line_offsets = {}
   chstate.line_lengths = {}

   local ok, ast, comments, code_lines, line_endings = pcall(function()
      return parser.parse(chstate.source, chstate.line_offsets, chstate.line_lengths)
   end)

   if not ok then
      -- The parser raises an instance of its own SyntaxError class, which has no
      -- `tag` field; without this check every parse error reported "table: 0x...".
      if type(ast) == "table" and utils.is_instance(ast, parser.SyntaxError) then
         return nil, ast
      end
      if type(ast) == "table" and ast.tag == "SyntaxError" then
         return nil, ast
      end
      return nil, {tag = "SyntaxError", msg = tostring(ast), line = 1,
         offset = 1, end_offset = 1}
   end

   chstate.ast = ast
   chstate.comments = comments
   chstate.code_lines = code_lines
   chstate.line_endings = line_endings

   unwrap_parens.run(chstate)
   linearize.run(chstate)
   name_functions.run(chstate)

   local remaining = count_nodes(ast, max_nodes + 1)
   chstate.resolved_locals = remaining > 0
   chstate.node_count = max_nodes + 1 - remaining

   if chstate.resolved_locals then
      resolve_locals.run(chstate)
   end

   return chstate
end

--- Line and column for a source offset, matching how luacheck reports positions.
function parse_context.offset_to_position(chstate, line, offset)
   local start = chstate.line_offsets[line] or 0
   local line_length = chstate.line_lengths[line]
   local column = offset - start + 1
   if line_len_available(line_length) and line_length then
      column = math.max(1, math.min(line_length, column))
   end
   return column, line
end

function line_len_available(value)
   return value ~= nil
end

return parse_context
