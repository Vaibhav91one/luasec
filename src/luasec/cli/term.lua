-- Terminal facts and colour. Colour is for people: it is on only when the stream
-- is a terminal (or --color forces it), never when NO_COLOR is set or --no-color
-- is given, and never in a pipe, so what a tool parses stays plain.
local term = {}

--- Is file descriptor `fd` (1 for stdout, 2 for stderr) a terminal? The command is
-- a constant and inherits this process's descriptors, so it answers for the real ones.
function term.is_tty(fd)
   if fd == 1 then return os.execute("test -t 1") == true end
   if fd == 2 then return os.execute("test -t 2") == true end
   if fd == 0 then return os.execute("test -t 0") == true end
   return false
end

local CODES = {
   bold = "1", dim = "2", red = "31", green = "32", yellow = "33", blue = "34",
   magenta = "35", cyan = "36",
}

--- A palette of functions that wrap text in colour. `enabled` is true (forced on),
-- false (forced off) or nil, which means: on when `fd` is a terminal, NO_COLOR is
-- unset or empty, and TERM is not "dumb".
function term.palette(enabled, fd)
   if enabled == nil then
      local no_color = os.getenv("NO_COLOR")
      enabled = (no_color == nil or no_color == "")
         and os.getenv("TERM") ~= "dumb"
         and term.is_tty(fd or 1)
   end
   local paint = {enabled = enabled}
   for name, code in pairs(CODES) do
      if enabled then
         paint[name] = function(text) return "\27[" .. code .. "m" .. text .. "\27[0m" end
      else
         paint[name] = function(text) return text end
      end
   end
   return paint
end

--- Single-key mode switches off the signal keys too (-isig), so Ctrl-C arrives
-- as a byte the reader sees as "quit" and can restore the terminal, instead
-- of a signal that kills the process with echo still off.
-- luasec: ignore 708  the stty command is a constant mode switch, never user input
function term.raw()
   os.execute("stty -icanon -echo -isig min 1")
end

-- luasec: ignore 708  the stty command is a constant mode switch, never user input
function term.cooked()
   os.execute("stty icanon echo isig")
end

--- A bar `width` cells wide, `fraction` (0 to 1) full.
function term.bar(fraction, width)
   local filled = math.max(0, math.min(width, math.floor(fraction * width + 0.5)))
   return string.rep("#", filled) .. string.rep("-", width - filled)
end

--- The same shape in block glyphs, for the doctor score panel.
function term.blocks(fraction, width)
   local filled = math.max(0, math.min(width, math.floor(fraction * width + 0.5)))
   return string.rep("█", filled) .. string.rep("░", width - filled)
end

--- The colour choice from the parsed options: false for --no-color, true for
-- --color, nil to decide from the stream (--no-color wins when both are given).
function term.choice(opts)
   if opts.no_color then return false end
   if opts.color then return true end
   return nil
end

local function has_utf8()
   return type(utf8) == "table"
      and type(utf8.len) == "function"
      and type(utf8.offset) == "function"
end

--- Display columns in `text`: characters, not bytes, so CJK and arrows count
-- once each. Invalid UTF-8 falls back to bytes rather than failing the draw.
local function dlen(text)
   if has_utf8() then
      local n = utf8.len(text)
      if n then return n end
   end
   return #text
end

-- Byte offset of the nth character (1-indexed); n past the end means #text+1.
local function char_byte(text, n)
   if has_utf8() and utf8.len(text) then
      if n < 1 then return 1 end
      return utf8.offset(text, n) or (#text + 1)
   end
   if n < 1 then return 1 end
   return math.min(#text + 1, n)
end

-- Characters `first`..`last` without ever cutting a multibyte sequence.
local function char_sub(text, first, last)
   if first > last then return "" end
   return text:sub(char_byte(text, first), char_byte(text, last + 1) - 1)
end

--- Display columns in `text`, for callers that budget a line from its parts.
function term.len(text)
   return dlen(text)
end

local function clamp(columns)
   if columns < 20 then return 20 end
   if columns > 500 then return 500 end
   return columns
end

--- Width from a `stty size` output string and a COLUMNS value: the stty
-- columns win, then COLUMNS when it is a positive integer, then 80.
-- Split out so it is unit-testable without a terminal.
function term.parse_width(stty_text, columns_text)
   if type(stty_text) == "string" then
      local columns = tonumber(stty_text:match("%d+%s+(%d+)"))
      if columns and columns >= 1 then return clamp(math.floor(columns)) end
   end
   if type(columns_text) == "string" then
      local columns = tonumber(columns_text:match("^%s*(%d+)%s*$"))
      if columns and columns >= 1 then return clamp(math.floor(columns)) end
   end
   return 80
end

--- Terminal column count: `stty size` from the controlling terminal, then
-- COLUMNS, then 80, clamped to 20..500. Read once per screen draw (cheap
-- enough); cached nowhere so a resize is seen on the next draw.
function term.width()
   local stty_text = ""
   local handle = io.popen("stty size 2>/dev/null </dev/tty") -- luasec: ignore 702  constant command, no user input
   if handle then
      stty_text = handle:read("*a") or ""
      handle:close()
   end
   return term.parse_width(stty_text, os.getenv("COLUMNS"))
end

--- Shorten `text` to at most `width` display columns, replacing the middle
-- with … so the start and the tail survive. Short text is unchanged.
function term.fit(text, width)
   width = math.floor(width or 80)
   local n = dlen(text)
   if n <= width then return text end
   if width <= 0 then return "" end
   if width == 1 then return "…" end
   local keep, front = width - 1, math.ceil((width - 1) / 2)
   return char_sub(text, 1, front) .. "…" .. char_sub(text, n - (keep - front) + 1, n)
end

--- Like fit, but a trailing last-segment `file:line` tail always survives:
-- the front gives way first. Text without such a tail fits generically.
function term.fit_path(text, width)
   width = math.floor(width or 80)
   if dlen(text) <= width then return text end
   local tail = type(text) == "string" and text:match("([^/%s]+:%d+)%s*$") or nil
   if not tail then return term.fit(text, width) end
   local tail_len = dlen(tail)
   if tail_len + 1 >= width then return term.fit(tail, width) end
   return char_sub(text, 1, width - tail_len - 1) .. "…" .. tail
end

--- Wrap `text` at word boundaries to lines of at most `width` display
-- columns. Lines that already fit are returned untouched, keeping their
-- spacing; a single token longer than the width is fitted with fit_path.
function term.wrap(text, width)
   width = math.floor(width or 80)
   if width < 1 then return {""} end
   if dlen(text) <= width then return {text} end
   local indent = text:match("^(%s*)") or ""
   local room = math.max(1, width - dlen(indent))
   local words = {}
   for token in text:gmatch("%S+") do
      -- A loop variable is read-only from Lua 5.5, so the fitted copy is a new local.
      local word = token
      if dlen(word) > room then word = term.fit_path(word, room) end
      words[#words + 1] = word
   end
   if #words == 0 then return {""} end
   local lines, current = {}, indent .. words[1]
   for index = 2, #words do
      if dlen(current) + 1 + dlen(words[index]) <= width then
         current = current .. " " .. words[index]
      else
         lines[#lines + 1] = current
         current = indent .. words[index]
      end
   end
   lines[#lines + 1] = current
   return lines
end

return term
