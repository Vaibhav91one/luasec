-- Arrow-key picker for small terminal menus. The caller owns the terminal:
-- pick only reads single bytes and writes rows, so it works on piped input
-- too. Up/Down and k/j wrap around the list; Enter selects the cursor row;
-- an item's `key` letter jumps straight to it; Esc, q, Ctrl-C, Ctrl-D and a
-- closed stdin go back (nil).
local term = require "luasec.cli.term"

local selector = {}

local HINT = "↑/↓ move · Enter select · Esc back · q quit"

local function dim(text)
   return "\27[2m" .. text .. "\27[0m"
end

local function flush(out)
   if out.flush then out:flush() end
end

local function row(context, item, mark, index)
   local line = ((index == mark) and "> " or "  ") .. item.key .. "  " .. item.label
   if item.recommended then
      line = line .. " (Recommended)"
   end
   if item.note then
      line = line .. "  " .. dim(item.note)
   end
   context.out:write(line .. "\n")
end

local function show(context, title, items, mark)
   context.out:write(title .. "\n")
   for index, item in ipairs(items) do
      row(context, item, mark, index)
   end
   context.out:write(dim(HINT) .. "\n")
   flush(context.out)
end

local function redraw(context, title, items, mark)
   local out = context.out
   out:write(("\27[%dA"):format(#items + 2))
   out:write("\27[K" .. title .. "\n")
   for index, item in ipairs(items) do
      out:write("\27[K")
      row(context, item, mark, index)
   end
   out:write("\27[K" .. dim(HINT) .. "\n")
   flush(out)
end

local function read_key()
   local first = io.read(1)
   if first == nil then return "quit" end
   if first == "\4" or first == "\3" then return "quit" end
   if first == "\27" then
      local second = io.read(1)
      if second == nil then return "escape" end
      if second ~= "[" then return "escape" end
      local third = io.read(1)
      if third == nil then return "escape" end
      if third == "A" then return "up" end
      if third == "B" then return "down" end
      return "ignore"
   end
   if first == "\r" or first == "\n" then return "enter" end
   if first == "k" then return "up" end
   if first == "j" then return "down" end
   if first == "q" then return "quit" end
   return first
end

--- Show `title`, one row per item and a hint line; return the picked index,
-- or nil on Esc/q/Ctrl-C/Ctrl-D/closed stdin. `opts.initial` is the cursor
-- row (default 1). Redraws in place on a terminal, writes once on a pipe.
function selector.pick(context, title, items, opts)
   context.out = context.out or io.stdout
   local mark = (opts and opts.initial) or 1
   if mark < 1 then mark = 1 end
   if mark > #items then mark = #items end
   local tty = term.is_tty(1)
   show(context, title, items, mark)
   while true do
      local key = read_key()
      if key == "quit" or key == "escape" then
         return nil
      elseif key == "up" then
         mark = mark - 1
         if mark < 1 then mark = #items end
         if tty then redraw(context, title, items, mark) end
      elseif key == "down" then
         mark = mark + 1
         if mark > #items then mark = 1 end
         if tty then redraw(context, title, items, mark) end
      elseif key == "enter" then
         return mark
      elseif key == "ignore" then
         -- unknown escape: stay where we are
      else
         for index, item in ipairs(items) do
            if item.key == key then
               return index
            end
         end
         -- any other byte: stay where we are
      end
   end
end

return selector
