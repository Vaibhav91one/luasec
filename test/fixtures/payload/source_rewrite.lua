-- Fixture: a build tool compiling its own source, reduced from
-- corpus/luajit/src/host/genlibbc.lua (issue #266).
--
-- `transform` is handed a block of source text that `read_source` took out of
-- this file's own text, rewrites the bytecode-access markers in it, and hands
-- the result to `load`. The replacement functions are closures, so every one of
-- them is a "gsub with a function replacement" - but each returns formatted
-- text, never a byte. Nothing is hidden, nothing is fetched, and nothing is
-- attacker-controlled: this is a program compiling the source it is holding in
-- the open, which is what the module already calls script loading rather than a
-- hidden payload.
local function format(fmt, ...)
   return string.format(fmt, ...)
end

local function transform(code)
   local n = -30000
   code = string.gsub(code, "CHECK_(%w*)%((.-)%)", function(tp, var)
      n = n + 1
      return format("%s=%d", var, n)
   end)
   code = string.gsub(code, "PAIRS%((.-)%)", function(var)
      return format("nil, %s, 0x4dp80", var)
   end)
   return "return " .. code
end

local function read_source(text)
   return text
end

local function compile(src, mode)
   for name, code in string.gmatch(src, "LIB%(([^)]*)%)%s*/%*(.-)%*/") do
      local tcode = transform(code)
      local func = assert(load(tcode, "", mode))
      return name, func
   end
end

return compile(read_source(SOURCE), "t")
