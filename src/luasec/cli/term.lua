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

return term
