-- Lua embedded in an nginx.conf (#296): the bodies of `*_by_lua_block { ... }` are scanned,
-- everything else in the file is blanked. Same contract as template.lua: every line break and
-- column outside a block is kept, so a finding lands on the nginx.conf's own line and column.
-- Each body is wrapped in `do ... end` (the opener and closer are overwritten in place), because a
-- handler may end in `return` and the bodies of several handlers share one chunk.
--
-- Not read: the old string form `content_by_lua '...'` and `*_by_lua_file` (the file it names is
-- ordinary Lua and is scanned as itself). A `#` inside a quoted nginx argument is read as a
-- comment up to the end of that line.
local nginxconf = {}

local OPENER = "_by_lua_block%s*{"

function nginxconf.is_conf_path(path)
   return path:lower():sub(-5) == ".conf"
end

function nginxconf.has_lua(text)
   return text:find(OPENER) ~= nil
end

local function blank(s)
   return (s:gsub("[^\r\n]", " "))
end

-- Index of the `}` closing a block whose body starts at `i`, or nil when it never closes.
-- Braces inside Lua strings, long strings and comments do not count, as in nginx's own lexer.
local function closing_brace(text, i)
   local depth, n = 1, #text
   while i <= n do
      local c = text:sub(i, i)
      local long = text:match("^%[(=*)%[", i)
      if c == "-" and text:sub(i + 1, i + 1) == "-" then
         long = text:match("^%[(=*)%[", i + 2)
         if long then
            local _, e = text:find("]" .. long .. "]", i + 4 + #long, true)
            i = (e or n) + 1
         else
            i = (text:find("\n", i, true) or n) + 1
         end
      elseif long then
         local _, e = text:find("]" .. long .. "]", i + 2 + #long, true)
         i = (e or n) + 1
      elseif c == '"' or c == "'" then
         i = i + 1
         while i <= n and text:sub(i, i) ~= c and text:sub(i, i) ~= "\n" do
            i = i + (text:sub(i, i) == "\\" and 2 or 1)
         end
         i = i + 1
      else
         if c == "{" then depth = depth + 1
         elseif c == "}" then
            depth = depth - 1
            if depth == 0 then return i end
         end
         i = i + 1
      end
   end
end

function nginxconf.extract(text)
   local out, pos = {}, 1
   while true do
      local hash = text:find("#", pos, true)
      local s, e = text:find(OPENER, pos)
      if not s then break end
      if hash and hash < s then
         -- an nginx comment: blank it to the end of its line and look again
         local eol = text:find("\n", hash, true) or #text + 1
         out[#out + 1] = blank(text:sub(pos, eol - 1))
         pos = eol
      else
         local close = closing_brace(text, e + 1) or #text + 1
         out[#out + 1] = blank(text:sub(pos, s - 1)) .. "do" .. blank(text:sub(s + 2, e))
         out[#out + 1] = text:sub(e + 1, close - 1)
         out[#out + 1] = close <= #text and "end" or ""
         pos = close + 1
      end
   end
   out[#out + 1] = blank(text:sub(pos))
   return table.concat(out)
end

return nginxconf
