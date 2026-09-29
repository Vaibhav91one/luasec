-- Rule module: rawscan.
--
-- A detector is a function(ctx). It calls ctx:emit(code, node, extra) for each
-- finding. See src/luasec/rules/context.lua for what a context offers.
--
-- Code this module owns: 902, 903, and the findings the raw path makes when
-- there is no check state to make them through - 711, 707 and the dynamic-arg
-- shapes of 701-706.
--
-- This module also owns the one pass that has no AST to work from.
-- `scan_source(source, opts)` takes raw text and lexes it, because a file the
-- parser rejected is exactly the file an attacker would like us to say nothing
-- about. A check state cannot help there: there is none.
--
-- Three properties the lexer below is built to have.
--
-- Linear. Every byte is read a bounded number of times and no Lua pattern is
-- ever applied to the source, so nothing in the input can make a matcher
-- backtrack. The operator table is an if-chain on the byte, not a loop over
-- candidates, and an identifier, a dotted path and a long string's text are
-- each capped, so no single token can make the pass quadratic in the file.
--
-- Honest about strings and comments. A name inside a string literal or a
-- comment is text, not code, and firmware files document themselves
-- ("-- replaced os.execute with our own"). Only bytes the lexer classifies as
-- code reach the pattern tables.
--
-- Bounded. The source length, the number of findings and the depth of the
-- expression that decides "is this argument constant" all have caps, and every
-- cap says so in a finding rather than passing for a clean result.
local codes = require "luasec.rules.codes"
local platform_api = require "luasec.registry.platform_api"
local profiles = require "luasec.registry.profiles"

local M = {}

local detectors = {}

-- ------------------------------------------------------------------- caps

-- Bytes of source the raw scan will read. A file above this gets one finding
-- saying the raw scan was skipped; it is not silence, and silence here would
-- read as "nothing to find".
M.MAX_SOURCE_BYTES = 32 * 1024 * 1024

-- Findings collected from one scan. Past this the scan keeps counting but
-- stops allocating, and reports the count it did not detail.
M.MAX_FINDINGS = 50

-- Tokens read while deciding whether a call's argument is a constant. A call
-- with more tokens than this is treated as dynamic, which is the direction that
-- cannot lose a finding.
M.MAX_ARG_TOKENS = 200

-- Longest identifier, and longest dotted path, the scan will look at. Real API
-- paths are far shorter; a longer one is not a name this tool has a code for.
M.MAX_NAME = 128

-- ----------------------------------------------------------------- findings

local function make_finding(code, line, column, name, detail)
   local spec = codes.get(code)
   local finding = {
      code = code,
      line = line or 1,
      column = column or 1,
      end_column = column or 1,
      severity = spec.severity,
      confidence = spec.confidence or "low",
      cwe = spec.cwe,
      name = name or "<raw scan>",
   }
   finding.message = codes.render(spec, finding)
   -- Kept as a field, not only folded into the message, so a detector that
   -- re-emits the finding through a rule context can carry the same words.
   finding.detail = detail
   if detail then finding.message = finding.message .. ": " .. detail end
   return finding
end

-- ----------------------------------------------------------------- patterns
--
-- Calls whose finding is the call itself, whatever the argument. The FFI
-- reaches libc, so reaching for it is the finding and no argument makes it
-- safe.
local SHAPE_CODES = {
   ["ffi.cdef"] = "707",
   ["ffi.C"] = "707",
   ["ffi.string"] = "707",
}

-- First segment of any path in SHAPE_CODES. A path that does not start with one
-- of these cannot match, and the lookup is what keeps match_path from walking
-- the whole table for every call in the file.
local SHAPE_ROOTS = {ffi = true}

-- Calls whose finding is the argument: with a constant there is nothing to
-- report, and telling a folded constant from a value is the taint engine's job.
-- A lexical scan can only see that the argument is not a literal it can read,
-- which is what "dynamic" means in the table below.
local DYNAMIC_CODES = {
   ["os.execute"] = "701",
   ["io.popen"] = "702",
   ["loadstring"] = "703",
   ["load"] = "703",
   ["dofile"] = "704",
   ["loadfile"] = "704",
   ["package.loadlib"] = "706",
   ["ffi.load"] = "706",
   ["require"] = "705",
}

-- First segment of any path in DYNAMIC_CODES, for the same reason as
-- SHAPE_ROOTS.
local DYNAMIC_ROOTS = {
   os = true, io = true, package = true, load = true, loadstring = true,
   dofile = true, loadfile = true, ffi = true, require = true,
}

-- ---------------------------------------------------------------- dialects
--
-- `--std` names platform API sets. A few of them also name a Lua standard,
-- and the ones that do are what 903 is about: a file read under one dialect
-- that uses another dialect's API is not the file the operator thinks it is.
local LUA_STANDARDS = {
   lua51 = true, lua52 = true, lua53 = true, lua54 = true, luajit = true,
}

--- Is `name` the name of a Lua standard this module knows about?
-- A caller that has to tell a platform API set from a Lua standard asks here,
-- so the two vocabularies stay in one place.
function M.is_standard(name)
   return type(name) == "string" and LUA_STANDARDS[name] == true
end

--- The Lua standard the operator configured, or nil.
-- `std` is the same string `--std` takes: "+" separated, a leading "+" meaning
-- "and the defaults". A table is accepted too, so a caller that already split
-- it does not have to join it back together.
function resolve_standard(std)
   local parts
   if type(std) == "table" then
      parts = std
   elseif type(std) == "string" then
      parts = {}
      for part in std:gmatch("[^+]+") do
         parts[#parts + 1] = (part:gsub("^%s+", ""):gsub("%s+$", ""))
      end
   else
      return nil
   end
   for _, part in ipairs(parts) do
      -- `luajit` names both a platform profile and a Lua standard, and both
      -- readings are wanted: the standard says which dialect the file is
      -- measured against, the profile says which APIs the FFI pack provides.
      if LUA_STANDARDS[part] then return part end
   end
   return nil
end

-- Capabilities a standard does not have. The key is a first path segment for
-- the API rows and a token for the syntax rows; the value lists the standards
-- that have it, plus whether the tool's own baseline has it.
--
-- The `baseline` flag is what the tool assumes when `--std` names no Lua
-- standard at all: the stock library of the dialect its parser reads, which is
-- 5.4. The FFI is not part of that, which is why `require("ffi")` with no
-- `--std` is worth reporting and not just noise.
--
-- Deliberately short. A standard is not a whitelist: reporting every API some
-- dialect lacks would report `table.concat` against an imagined 5.0 and drown
-- the finding that matters. These are the capabilities that change what a line
-- of firmware code can do, so a mismatch here is a claim about the code rather
-- than about a version number. LuaJIT gets its own rows because it is a 5.1
-- dialect that has the FFI and not the 5.3 operators, which makes it the case
-- where a version number alone would be wrong.
local CAPABILITIES = {
   ffi = {luajit = true},
   jit = {luajit = true},
   bit32 = {lua52 = true, lua53 = true},
   const_attribute = {lua54 = true, baseline = true},
   close_attribute = {lua54 = true, baseline = true},
   integer_division = {lua53 = true, lua54 = true, baseline = true},
   shift_left = {lua53 = true, lua54 = true, baseline = true},
   shift_right = {lua53 = true, lua54 = true, baseline = true},
   bitwise_not = {lua53 = true, lua54 = true, baseline = true},
}

--- Does the configured standard provide a capability?
local function provides(standard, capability)
   local set = CAPABILITIES[capability]
   if standard then return set[standard] == true end
   return set.baseline == true
end

-- Operator text to the capability it needs. `~=` is not here on purpose: it is
-- spelled with the same byte as `~` and means "not equal" in every version.
local SYNTAX_CAPABILITY = {
   ["//"] = "integer_division",
   ["<<"] = "shift_left",
   [">>"] = "shift_right",
   ["~"] = "bitwise_not",
}

-- -------------------------------------------------------------------- lexer
--
-- 903 says an API is unavailable in the environment the operator described. If a
-- loaded platform profile provides it, the environment does provide it and there
-- is nothing to report: every LuCI call is "outside the Lua standard", and saying
-- so 257 times told nobody anything.
local function provided_by_profile(path)
   if not path then return false end
   return platform_api.match_source(path) ~= nil
      or platform_api.match_sink(path) ~= nil
      or platform_api.match_shape(path) ~= nil
      or platform_api.match_propagator(path) ~= nil
end

-- Token kinds: name, number, string, backtick, op, eof.
--
-- The fifth return value says whether the token's text is its value. It is
-- false for a string containing a `\` (whose value depends on escapes this
-- scan does not decode) and for a name or a long string past the caps. A
-- caller that needs the value and does not have it says nothing, rather than
-- matching on bytes that may not be what the interpreter would see.
local Lexer = {}
Lexer.__index = Lexer

local function new_lexer(source)
   return setmetatable({
      src = source,
      n = #source,
      pos = 1,
      line = 1,
      line_start = 1,
      -- Where an unterminated long bracket started: the line, and the offset
      -- its body began at. Set on the lexer rather than returned, so a lookahead
      -- that rewinds the position cannot lose it and one that consumes it
      -- cannot swallow it.
      unread_line, unread_from = nil, nil,
   }, Lexer)
end

local function is_space(b)
   return b == 32 or b == 9 or b == 10 or b == 11 or b == 12 or b == 13
end

local function is_digit(b)
   return b ~= nil and b >= 48 and b <= 57
end

local function is_alpha(b)
   return b ~= nil and ((b >= 97 and b <= 122) or (b >= 65 and b <= 90) or b == 95)
end

local function is_alnum(b)
   return is_alpha(b) or is_digit(b)
end

--- Skip whitespace, counting lines.
-- A line break here is the line feed only: luaseck decodes CRLF and CR to LF
-- before the analyzer sees the text, and the raw scan counts what it reads.
function Lexer:skip_space()
   while self.pos <= self.n do
      local b = self.src:byte(self.pos)
      if b == 10 then
         self.line = self.line + 1
         self.line_start = self.pos + 1
         self.pos = self.pos + 1
      elseif is_space(b) then
         self.pos = self.pos + 1
      else
         return
      end
   end
end

function Lexer:column()
   return self.pos - self.line_start + 1
end

-- Save and restore the lexer's whole state, so a caller can look at the next few
-- tokens without committing to them. Three primitives, no allocation.
function Lexer:mark()
   return {pos = self.pos, line = self.line, line_start = self.line_start}
end

function Lexer:reset(mark)
   self.pos = mark.pos
   self.line = mark.line
   self.line_start = mark.line_start
end

-- Is a long bracket opening here? Returns its level, or nil.
function Lexer:long_bracket_level()
   if self.src:byte(self.pos) ~= 91 then return nil end
   local level, at = 0, self.pos + 1
   while self.src:byte(at) == 61 do
      level = level + 1
      at = at + 1
   end
   if self.src:byte(at) == 91 then return level end
   return nil
end

-- Consume through the `]` + level `=` + `]` that closes a long bracket whose
-- body starts at the current position. Returns the offset after the close, or
-- nil when the file ends first. Searching for a two- or three-byte close is
-- linear, and the level means no input can make it rescan.
--
-- Newlines inside the body are counted here rather than in skip_space, which
-- never sees them; line_start moves with them so the next token's column is
-- counted from the right line.
function Lexer:long_bracket_end(level)
   -- One allocation rather than a `close = close .. "="` loop: the number of
   -- equals signs is the level, which the file chooses, and a loop that grows
   -- a string by input is the shape this tool warns other code about.
   local close = "]" .. string.rep("=", level) .. "]"

   local found = self.src:find(close, self.pos, true)
   if not found then return nil end

   local count, last_newline, from = 0, nil, self.pos
   while true do
      local nl = self.src:find("\n", from, true)
      if not nl or nl >= found then break end
      count = count + 1
      last_newline = nl
      from = nl + 1
   end
   self.line = self.line + count
   if last_newline then self.line_start = last_newline + 1 end

   return found + #close
end

-- Skip a comment: `--` then a long bracket is a long comment, otherwise
-- everything to the end of the line is one.
--
-- An unclosed long comment runs to the end of the file - that is the lexer's
-- own reading, not a guess - and every byte after it is comment text rather
-- than code. `unread_line` records where that started, so the caller can say
-- how much of the file it did not read.
function Lexer:skip_comment()
   self.pos = self.pos + 2
   local level = self:long_bracket_level()
   if level then
      self.pos = self.pos + 1 + level
      local after = self:long_bracket_end(level)
      if after then
         self.pos = after
         return
      end
      self.unread_line = self.unread_line or self.line
      self.unread_from = self.unread_line and self.pos or nil
      self.pos = self.n + 1
      return
   end
   while self.pos <= self.n and self.src:byte(self.pos) ~= 10 do
      self.pos = self.pos + 1
   end
   return nil
end

-- The operator starting at the current position, and its length. An if-chain on
-- the byte rather than a scan of a candidate list, so a 5 MB file of `+` costs
-- 5 MB and not 5 MB times the number of operators.
function Lexer:operator()
   local b = self.src:byte(self.pos)
   local b2 = self.src:byte(self.pos + 1)
   local b3 = self.src:byte(self.pos + 2)
   if b == 46 then -- .
      if b2 == 46 then return b3 == 46 and "..." or "..", b3 == 46 and 3 or 2 end
      return ".", 1
   elseif b == 58 then
      return b2 == 58 and "::" or ":", b2 == 58 and 2 or 1
   elseif b == 61 then
      return b2 == 61 and "==" or "=", b2 == 61 and 2 or 1
   elseif b == 126 then -- ~
      return b2 == 61 and "~=" or "~", b2 == 61 and 2 or 1
   elseif b == 60 then -- <
      if b2 == 61 then return "<=", 2 end
      if b2 == 60 then return "<<", 2 end
      return "<", 1
   elseif b == 62 then -- >
      if b2 == 61 then return ">=", 2 end
      if b2 == 62 then return ">>", 2 end
      return ">", 1
   elseif b == 47 then -- /
      return b2 == 47 and "//" or "/", b2 == 47 and 2 or 1
   end
   return string.char(b), 1
end

--- Next token: kind, value, line, column, value_known.
function Lexer:next_token()
   -- A loop, not recursion: a file of nothing but comment lines would put one
   -- Lua frame on the stack per line, and the stack is the one thing here that
   -- is not sized by the input.
   while true do
      self:skip_space()
      if self.pos > self.n then
         return "eof", nil, self.line, self:column(), true
      end

      local b = self.src:byte(self.pos)
      local line, column = self.line, self:column()

      if (b == 35 and self.pos == 1) or (b == 45 and self.src:byte(self.pos + 1) == 45) then
         -- A shebang is skipped by the interpreter, and `--` starts a comment.
         -- Both are text, so both go back around the loop.
         self:skip_comment()
      elseif is_alpha(b) then
         local start = self.pos
         repeat self.pos = self.pos + 1 until not is_alnum(self.src:byte(self.pos))
         if self.pos - start > M.MAX_NAME then
            return "name", nil, line, column, false
         end
         return "name", self.src:sub(start, self.pos - 1), line, column, true
      elseif is_digit(b) or (b == 46 and is_digit(self.src:byte(self.pos + 1))) then
         -- The value is not needed; only where the token stops.
         local last
         repeat
            last = self.src:byte(self.pos)
            self.pos = self.pos + 1
         until not (is_alnum(last) or last == 46)
         -- The loop reads one byte past the number to find its end. That byte
         -- is not part of the token - and when it is a newline, skip_space is
         -- what has to count it - so it is given back.
         self.pos = self.pos - 1
         if last == 101 or last == 69 or last == 112 or last == 80 then
            local sign = self.src:byte(self.pos)
            if sign == 43 or sign == 45 then self.pos = self.pos + 1 end
         end
         return "number", nil, line, column, true
      elseif b == 34 or b == 39 then
         return self:short_string(b, line, column)
      elseif b == 96 then
         return self:backtick(line, column)
      elseif b == 91 then
         local level = self:long_bracket_level()
         if level then
            self.pos = self.pos + 1 + level
            local start = self.pos
            local after = self:long_bracket_end(level)
            if after then
               local finish = after - 1 - level - 1
               local text = finish > start and self.src:sub(start, finish) or ""
               self.pos = after
               -- A long string has no escapes, so its text is its value.
               if #text > M.MAX_NAME then
                  return "string", nil, line, column, false
               end
               return "string", text, line, column, true
            end
            -- Unterminated: to the end of the file everything is string
            -- content, and reporting inside it would be inventing code.
            self.pos = self.n + 1
            if not self.unread_line then
               self.unread_line, self.unread_from = line, start
            end
            return "string", nil, line, column, false
         end
         local op, length = self:operator()
         self.pos = self.pos + length
         return "op", op, line, column, true
      else
         local op, length = self:operator()
         self.pos = self.pos + length
         return "op", op, line, column, true
      end
   end
end

-- A quoted string. A backslash means the text is not the value, so the value is
-- reported as unknown rather than guessed at. An unterminated short string
-- cannot span a newline in Lua, so it ends with its line and the rest of the
-- file is code again.
function Lexer:short_string(quote, line, column)
   self.pos = self.pos + 1
   local start = self.pos
   local plain = true
   while self.pos <= self.n do
      local b = self.src:byte(self.pos)
      if b == 92 then -- backslash
         plain = false
         local escaped = self.src:byte(self.pos + 1)
         self.pos = self.pos + 2
         if escaped == 10 then
            self.line = self.line + 1
            self.line_start = self.pos
         end
      elseif b == quote then
         local text = self.src:sub(start, self.pos - 1)
         self.pos = self.pos + 1
         if not plain or #text > M.MAX_NAME then
            return "string", nil, line, column, false
         end
         return "string", text, line, column, true
      elseif b == 10 then
         break
      else
         self.pos = self.pos + 1
      end
   end
   return "string", nil, line, column, false
end

-- A backtick command literal, Lua 5.2 and later. The bytes between the
-- backticks are a shell command and not Lua, so the lexer hands them over
-- whole and never looks inside them for Lua patterns.
function Lexer:backtick(line, column)
   self.pos = self.pos + 1
   local start = self.pos
   while self.pos <= self.n do
      local b = self.src:byte(self.pos)
      if b == 96 then
         local text = self.src:sub(start, self.pos - 1)
         self.pos = self.pos + 1
         return "backtick", text, line, column, true
      elseif b == 10 then
         break
      end
      self.pos = self.pos + 1
   end
   return "backtick", self.src:sub(start, self.pos - 1), line, column, false
end

-- ------------------------------------------------------------------ helpers

-- The two attribute names Lua 5.4 defines. Matching only these two is what
-- keeps `<` from being read as an attribute in `if a < close > b`: a variable
-- called `close` in a chained comparison is the one shape that can still
-- produce a false 902, and a two-element set is a cheap price for it.
local ATTRIBUTE_NAMES = {const = true, close = true}

--- Read a Lua 5.4 attribute if one follows, and consume it.
-- The first token after the name must already have been read and must be `<`;
-- it is not given back, because it is either part of the attribute or the
-- caller resets. Returns the attribute name, or nil with the lexer put back
-- where it was.
function read_attribute(lex, first_kind, first_value)
   if first_kind ~= "op" or first_value ~= "<" then return nil end
   local kind, value = lex:next_token()
   if kind ~= "name" or not ATTRIBUTE_NAMES[value] then return nil end
   local after, closer = lex:next_token()
   if after ~= "op" or closer ~= ">" then return nil end
   return value
end

--- Read `require("<module>")` or `require "<module>"` if that is what comes next.
-- Returns the module name when the literal is one whose value the scan can
-- read, or nil with the lexer put back where it was. A module name built at
-- run time is not readable, and a scan that guessed at it would be inventing
-- the API.
function read_require_module(lex)
   local mark = lex:mark()
   local function unreadable()
      lex:reset(mark)
      return nil
   end

   local kind, value = lex:next_token()
   if kind ~= "name" or value ~= "require" then return unreadable() end

   local open_kind, open_value = lex:next_token()
   if open_kind == "string" then
      return open_value
   end
   if open_kind ~= "op" or open_value ~= "(" then return unreadable() end

   local module_kind, module, _, _, module_known = lex:next_token()
   if module_kind ~= "string" or not module_known then return unreadable() end
   kind, value = lex:next_token()
   if kind ~= "op" or value ~= ")" then return unreadable() end
   return module
end

--- Is a call's argument list a value the scan can read?
-- False (constant) only for literals, parenthesised literals, and the operators
-- that combine them. Everything else - a name, a nested call, a table
-- constructor, an index, a comparison, an unknown literal, or more tokens than
-- the cap - is dynamic, and dynamic is the direction that can still report the
-- sink. Reading a table constructor as a constant would be a false negative on
-- a line that cannot possibly be one.
local function arguments_are_dynamic(lex)
   local depth = 0
   for _ = 1, M.MAX_ARG_TOKENS do
      local kind, value, _, _, known = lex:next_token()
      if kind == "eof" then return true end
      if kind == "op" then
         if value == "(" then
            depth = depth + 1
         elseif value == ")" then
            if depth == 0 then return false end
            depth = depth - 1
         elseif value ~= ".." and value ~= "+" and value ~= "-" then
            return true
         end
      elseif kind == "name" or kind == "backtick" then
         return true
      elseif kind == "string" and not known then
         return true
      end
   end
   return true
end

-- The longest key of `table` that `path` starts with, at a `.` boundary or all
-- of it. `roots` is a small gate: a path whose first segment is not in it has
-- no key to match, so most calls cost one table lookup instead of a scan of
-- every key.
local function match_path(roots, table, path)
   local first = path
   local dot = path:find(".", 1, true)
   if dot then first = path:sub(1, dot - 1) end
   if not roots[first] then return nil, nil end

   local best, best_code
   for candidate, code in pairs(table) do
      if path == candidate then
         return candidate, code
      elseif #candidate < #path and path:sub(1, #candidate) == candidate
            and path:byte(#candidate + 1) == 46 then
         if not best or #candidate > #best then
            best, best_code = candidate, code
         end
      end
   end
   return best, best_code
end

-- ------------------------------------------------------------- raw scan

--- Lex raw source and report the patterns visible in it, whether or not the
-- parser would have accepted the file. Returns findings in source order.
--
-- Options:
--   std            configured platform API sets, e.g. "luajit" or "openwrt+luci"
--   max_bytes      override MAX_SOURCE_BYTES
--   max_findings   override MAX_FINDINGS
function M.scan_source(source, opts)
   opts = opts or {}
   local findings = {}
   if type(source) ~= "string" then return findings end

   local max_bytes = opts.max_bytes or M.MAX_SOURCE_BYTES
   local max_findings = opts.max_findings or M.MAX_FINDINGS
   local suppressed = 0

   local dialect_only = opts.dialect_only and true or false

   local function report(finding)
      if dialect_only and finding.code ~= "903" then return end
      -- Only 903 is about the environment. A shape finding names an API we
      -- recognize, which is the whole point of recognizing it.
      if finding.code == "903" and provided_by_profile(finding.name) then return end
      if #findings < max_findings then
         findings[#findings + 1] = finding
      else
         suppressed = suppressed + 1
      end
   end

   if #source > max_bytes then
      report(make_finding("901", 1, 1, "raw scan skipped", ("%d bytes is over the %d byte raw scan limit, so the file was not read"):format(#source, max_bytes)))
      return findings
   end

   local lex = new_lexer(source)
   local standard = resolve_standard(opts.std)
   local standard_name = standard or "the stock Lua library this tool reads by default"

   -- The dotted path being read, where its last segment started, and whether the
   -- next name continues it.
   local path, path_line, path_column, expect_dot = nil, 1, 1, false
   -- True between the `local` keyword and the `=` that ends its name list: the
   -- only place Lua 5.4 lets an attribute appear, and so the only place this
   -- parser accepts one. An attribute there is not why a file failed to parse,
   -- so it is never a 902; whether the standard even has attributes is a
   -- separate question, answered by dialect() below.
   local in_local_names, just_local = false, false
   -- Locals bound to a capability by `local f = require("ffi")`. A binding is
   -- the use: whatever the local is called, `f.C` is the FFI.
   local aliases = {}
   -- What `path`'s first segment stands for when that segment is a local bound
   -- to a capability, and the segment as it was written. Both are needed: the
   -- alias may be shorter or longer than the capability it names, and the path
   -- has to be rewritten from the segment that was actually read.
   local path_alias, path_head = nil, nil

   -- A capability the configured standard does not have, reported once per
   -- capability. Forty uses of ffi.C are one fact about the file, not forty
   -- findings, and the finding cap is better spent on what is different.
   local reported = {}

   local function dialect(capability, label, at_line, at_column)
      if provides(standard, capability) or reported[capability] then return end
      reported[capability] = true
      report(make_finding("903", at_line, at_column, label,
         ("%s is not part of %s"):format(label, standard_name)))
   end

   -- The path is complete: report it if it names a shape, and forget it. Called
   -- at every point a path can end - a new name, any operator but `.`, a
   -- string, a backtick, the end of the file - so a path never survives a line
   -- break and two unrelated lines cannot be read as one call.
   local function end_path()
      if not path then return end
      -- Read the path through the alias, so the finding names the capability
      -- rather than a local a reader cannot search for in their own file.
      local subject = path_alias and (path_alias .. path:sub(#path_head + 1)) or path
      local matched, code = match_path(SHAPE_ROOTS, SHAPE_CODES, subject)
      if matched then
         report(make_finding(code, path_line, path_column, subject))
      end
      path, path_alias, path_head, expect_dot = nil, nil, nil, false
   end

   while true do
      local kind, value, line, column = lex:next_token()
      if kind == "eof" then
         end_path()
         break
      end

      if kind == "name" then
         if not value then
            -- A name past the identifier cap. It is not a name this tool has a
            -- code for and not a path segment either, so it ends whatever path
            -- was open and is otherwise passed over. It still cost its bytes,
            -- once, and the loop still advances.
            end_path()
         elseif expect_dot and path then
            -- Over the path cap the same holds: no key in any table above is
            -- this long, so carrying it further would only cost time.
            if #path + #value + 1 <= M.MAX_NAME then
               path = path .. "." .. value
               path_line, path_column = line, column
            else
               end_path()
            end
         else
            end_path()
            path = value
            path_alias, path_head = aliases[value], value
            path_line, path_column = line, column
            if value == "local" then
               in_local_names, just_local = true, true
            elseif just_local then
               -- The first name after `local`. `function` there is the
               -- local-function form, which takes no attribute list at all.
               in_local_names = value ~= "function"
               just_local = false
            end
         end

         -- Read above, cleared here: the next name starts a new path unless a
         -- `.` says otherwise.
         expect_dot = false

         if path and value ~= "local" then
            -- One token of lookahead answers two questions at once: is this
            -- name being *used* as an API, and is an attribute following it.
            local mark = lex:mark()
            local next_kind, next_value = lex:next_token()

            -- A name is a use of a capability when something is done with it -
            -- a field read (`ffi.C`) or a call (`jit.flush()`). A name that is
            -- only being assigned, listed in a table constructor or used as an
            -- argument is a name, and reporting it would fire on every module
            -- table in the tool, this one included.
            local used = next_kind == "op"
               and (next_value == "." or next_value == "(")
            if used then
               -- A capability named by an identifier, whether it stands alone
               -- or is the first segment of a path. The first mention in the
               -- file is where the finding goes: a reader who opens there sees
               -- the code reach for the capability, and a file that names it
               -- forty times needs one finding, not forty.
               local capability = path_alias or path:match("^[^.]+")
               if CAPABILITIES[capability] then
                  dialect(capability, capability, line, column)
               end
            end

            local attribute = read_attribute(lex, next_kind, next_value)
            if attribute then
               local label = "<" .. attribute .. "> attribute"
               dialect(attribute .. "_attribute", label, line, column)
               if not in_local_names then
                  report(make_finding("902", line, column, label))
               end
            else
               lex:reset(mark)
            end
         end
      elseif kind == "op" and value == "." and path then
         expect_dot = true
      else
         local finished = path
         if not (kind == "op" and value == ".") then
            end_path()
            in_local_names, just_local = false, false
         end

         if kind == "op" and value == "=" and finished then
            -- `local f = require("ffi")` binds the FFI to a name of the
            -- author's choosing; every later `f.` is that capability.
            local module = read_require_module(lex)
            if module and CAPABILITIES[module] and not finished:find(".", 1, true) then
               aliases[finished] = module
               dialect(module, module, line, column)
            end
         elseif kind == "op" and value == "(" and finished then
            local matched, dynamic = match_path(DYNAMIC_ROOTS, DYNAMIC_CODES, finished)
            if matched and arguments_are_dynamic(lex) then
               report(make_finding(dynamic, line, column, finished))
            end
         elseif kind == "op" and SYNTAX_CAPABILITY[value] then
            dialect(SYNTAX_CAPABILITY[value], value, line, column)
         elseif kind == "op" and value == "," then
            -- Another name in the same local declaration follows.
            just_local = false
         elseif kind == "backtick" then
            -- Two true things about the same byte range. The command is the
            -- security claim (711), and the dialect is the reason the file has no
            -- AST at all (902). Reporting only the first would let a reader
            -- assume the rest of the file was analyzed; it was not.
            report(make_finding("711", line, column, "backtick command literal"))
            report(make_finding("902", line, column, "backtick command literal"))
         end
      end
   end

   if lex.unread_line then
      -- Nothing in the catalogue describes "the scan could not read this", and
      -- inventing a code for it here would put a number in the report that
      -- docs/rules.md does not explain. 901 with the count in the message is
      -- the honest shape: this file is not clean, and here is the part nobody
      -- looked at.
      report(make_finding("901", lex.unread_line, 1, "unread tail", (
         "a long bracket opened on line %d never closed, so the %d bytes from there to the "
         .. "end of the file are text the raw scan did not read as code"):format(
         lex.unread_line, lex.n - (lex.unread_from or 1))))
   end

   if suppressed > 0 then
      findings[#findings + 1] = make_finding("901", 1, 1, "raw scan truncated", (
         "%d further raw findings were not detailed, which is over the %d finding cap"):
         format(suppressed, max_findings))
   end

   return findings
end

--- The source as plain bytes, or nil when it is neither shape.
--
-- `scan_source` is handed text. A rule context is handed what the parser built
-- from it, which is a `Chars` object rather than a string: luacheck's lexer
-- wants Unicode-aware indexing and this scan wants the bytes. One
-- `get_substring` across the whole thing is the documented way to get them
-- back, and it is the only place this module pays for the difference.
local function source_text(source)
   if type(source) == "string" then return source end
   if type(source) == "table" and type(source.get_substring) == "function"
         and type(source.get_length) == "function" then
      return source:get_substring(1, source:get_length())
   end
   return nil
end

-- A node at a position the raw scan reported, so a detector can go through
-- ctx:emit and get the same finding shape every other rule produces.
local function node_at(ctx, line, column)
   return {
      tag = "Id",
      line = line,
      offset = (ctx.chstate.line_offsets[line] or 0) + column,
      end_offset = (ctx.chstate.line_offsets[line] or 0) + column,
   }
end

--- 903 on a file that parsed.
--
-- The raw scan is not the only reader of "is this API in the configured
-- standard": a file that parsed needs the same answer, and a second
-- implementation of the table above would be free to disagree with the first.
-- So this runs the same pass and keeps only its 903s. A parsed file has no
-- construct the parser cannot handle (that is what parsing means) and its
-- shapes are already reported by the platform registry, which resolves module
-- aliases the raw scan cannot, so the other codes are not repeated here.
local function detect_dialect(ctx)

   -- `--no-raw-scan` is documented as "skip the lexical scan", and this is one:
   -- it costs a second pass over every file that parsed. An operator who turns
   -- it off is asking for the AST-only answer, and gets it.
   if ctx.opts.no_raw_scan then return end
   local source = source_text(ctx.source)
   if not source then return end

   for _, finding in ipairs(M.scan_source(source, {std = ctx.opts.std,
                                                    dialect_only = true})) do
      local emitted = ctx:emit(finding.code, node_at(ctx, finding.line, finding.column),
         {name = finding.name})
      -- The registered message says the API is not in the configured standard.
      -- Which standard that is, and that no Lua standard was configured at all,
      -- is the part a reader cannot get from the code alone.
      emitted.message = emitted.message .. ": " .. finding.detail
   end
end

detectors[#detectors + 1] = detect_dialect

--- The detectors this module contributes, in run order.
function M.detectors()
   return detectors
end

return M
