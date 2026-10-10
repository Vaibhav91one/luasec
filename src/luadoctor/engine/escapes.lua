-- Lua 5.1 unknown-escape retry helper.
--
-- Lua 5.1 accepts an unknown escape inside a short string by dropping the
-- backslash (`"<\/a>"` is `</a>`), but the vendored lexer's short-string
-- scanner rejects it with "invalid escape sequence", so the whole file falls
-- back to a 901 with no flow analysis. normalise rewrites only those unknown
-- escapes so a retry parse sees the same lines and columns.
--
-- Rule: `\c` (c not a valid escape start) becomes `\\` when c is a single
-- byte: same length, so every line and column is unchanged. The string gains
-- a backslash instead of dropping one, which is irrelevant to the analysis.
-- A multibyte c cannot take a one-byte rewrite without shifting columns, so
-- it is left untouched (rare). Valid escapes, long strings and comments are
-- never touched.
local escapes = {}

local function is_digit(byte)
   return byte >= 48 and byte <= 57
end

local function is_newline_byte(byte)
   return byte == 10 or byte == 13
end

-- Valid single-byte escape starts per vendor/luacheck/lexer.lua: the simple
-- escapes a b f n r t v \ " ', a line continuation, and the multi-byte
-- escapes x (hex), u (UTF-8), z (whitespace zap) and decimal digits, whose
-- tails the lexer validates itself under different error messages.
local function is_valid_start(byte)
   return byte == 97 or byte == 110 or byte == 114 or byte == 116
      or byte == 98 or byte == 102 or byte == 118
      or byte == 92 or byte == 34 or byte == 39
      or byte == 120 or byte == 117 or byte == 122
      or is_digit(byte)
end

-- Skip a long bracket opened at `opened` (`[` or `--[[`) with `level` `=`
-- signs. Returns the index just past the matching close, or n + 1.
local function skip_long(source, opened, level, n)
   local i = opened
   while i <= n do
      if source:byte(i) == 93 then
         local j = i + 1
         while j <= n and source:byte(j) == 61 do j = j + 1 end
         if source:byte(j) == 93 and (j - i - 1) == level then return j + 1 end
      end
      i = i + 1
   end
   return n + 1
end

-- Level of the long bracket opening at index i (`[` or `--[`), or nil.
local function open_level(source, i, n)
   local j = i + 1
   while j <= n and source:byte(j) == 61 do j = j + 1 end
   if j <= n and source:byte(j) == 91 then return j - i - 1, j + 1 end
   return nil
end

function escapes.normalise(source)
   local n = #source
   local i = 1
   local last = 1
   local parts = nil
   while i <= n do
      local byte = source:byte(i)
      if byte == 45 and source:byte(i + 1) == 45 then
         local level = open_level(source, i + 2, n)
         if level then
            i = skip_long(source, i, level, n)
         else
            i = i + 2
            while i <= n and not is_newline_byte(source:byte(i)) do i = i + 1 end
         end
      elseif byte == 34 or byte == 39 then
         local quote = byte
         i = i + 1
         while i <= n do
            local c = source:byte(i)
            if c == quote then
               i = i + 1
               break
            elseif c == 92 then
               local e = source:byte(i + 1)
               if e == nil then
                  break
               elseif is_newline_byte(e) or is_valid_start(e) then
                  i = i + 2
               elseif e < 128 then
                  parts = parts or {}
                  parts[#parts + 1] = source:sub(last, i) .. "\\"
                  last = i + 2
                  i = i + 2
               else
                  i = i + 2
               end
            elseif is_newline_byte(c) then
               break
            else
               i = i + 1
            end
         end
      elseif byte == 91 then
         local level, after = open_level(source, i, n)
         if level then
            i = skip_long(source, after, level, n)
         else
            i = i + 1
         end
      else
         i = i + 1
      end
   end
   if not parts then return source end
   parts[#parts + 1] = source:sub(last)
   return table.concat(parts)
end

return escapes
