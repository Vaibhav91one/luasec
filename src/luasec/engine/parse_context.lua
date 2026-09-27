-- Builds a luacheck check state for one source file: decode, parse, then the
-- linearize + resolve_locals stages that give us a CFG and flow-sensitive
-- reaching definitions. We deliberately do not run luacheck's lint stages; we
-- only want its front end and dataflow.
--
-- Returns:
--   ok, chstate          on success
--   nil, syntax_error    when the source does not parse
local decoder = require "luacheck.decoder"
local parser = require "luacheck.parser"
local check_state = require "luacheck.check_state"
local unwrap_parens = require "luacheck.stages.unwrap_parens"
local linearize = require "luacheck.stages.linearize"
local name_functions = require "luacheck.stages.name_functions"
local resolve_locals = require "luacheck.stages.resolve_locals"

local parse_context = {}

function parse_context.build(source_bytes)
   local chstate = check_state.new(source_bytes)
   chstate.source = decoder.decode(source_bytes)
   chstate.line_offsets = {}
   chstate.line_lengths = {}

   local ok, ast, comments, code_lines, line_endings = pcall(function()
      return parser.parse(chstate.source, chstate.line_offsets, chstate.line_lengths)
   end)

   if not ok then
      if type(ast) == "table" and ast.tag == "SyntaxError" then
         return nil, ast
      end
      return nil, {tag = "SyntaxError", msg = tostring(ast)}
   end

   chstate.ast = ast
   chstate.comments = comments
   chstate.code_lines = code_lines
   chstate.line_endings = line_endings

   unwrap_parens.run(chstate)
   linearize.run(chstate)
   name_functions.run(chstate)
   resolve_locals.run(chstate)

   return chstate
end

-- Line/column for a source offset, matching how luacheck reports positions.
function parse_context.offset_to_position(chstate, line, offset)
   local start = chstate.line_offsets[line] or 0
   local line_len = chstate.line_lengths[line]
   local column = offset - start + 1
   if line_len then
      column = math.max(1, math.min(line_len, column))
   end
   return column, line
end

return parse_context
