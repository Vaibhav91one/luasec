-- Progress on stderr. A scan of a real firmware tree takes seconds to minutes
-- and used to say nothing, which looks the same as a hang. This module only
-- writes to stderr and only when asked or when stderr is a terminal, so the
-- report on stdout, a --score, and a CI log are never touched.
local term = require "luasec.cli.term"
local progress = {}

local SPINNER = {"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

local Progress = {}
Progress.__index = Progress

-- Is stderr a terminal? `test -t 2` inherits this process's stderr, so it
-- answers for the real one. See term.is_tty.
local function stderr_is_terminal()
   return term.is_tty(2)
end

--- A progress reporter for a run. `opts.progress` is true for --progress and
-- false for --no-progress; unset means "only on a terminal". --quiet always wins.
function progress.new(opts)
   local enabled
   if opts.quiet then
      enabled = false
   elseif opts.progress ~= nil then
      enabled = opts.progress
   else
      enabled = stderr_is_terminal()
   end
   return setmetatable({
      enabled = enabled,
      -- Rewrite one line in place only where there is a screen to rewrite.
      live = enabled and stderr_is_terminal(),
      started = os.time(),
      last_step = -1,
      line_open = false,
      frame = 0,
      paint = term.palette(term.choice(opts), 2),
   }, Progress)
end

-- Wipe a half-written counter line so a permanent line or the report starts clean.
function Progress:clear()
   if self.live and self.line_open then
      io.stderr:write("\r\27[K")
      self.line_open = false
   end
end

--- A permanent line.
function Progress:say(text)
   if not self.enabled then return end
   self:clear()
   io.stderr:write(self.paint.dim("lua-doctor:"), " ", text, "\n")
end

--- What the run is doing between counters, e.g. finding files or building
-- the report. On a terminal it holds the spinner line; otherwise it is one
-- permanent line, exactly like say.
function Progress:phase(text)
   if not self.enabled then return end
   if not self.live then
      self:say(text)
      return
   end
   self:clear()
   self.frame = self.frame % #SPINNER + 1
   io.stderr:write("\r\27[K", self.paint.cyan(SPINNER[self.frame]), " ", text, "  ")
   self.line_open = true
end

local function tail(path, width)
   if #path <= width then return path end
   return "..." .. path:sub(-(width - 3))
end


--- File number `done` of `total` is about to be analyzed.
function Progress:file(done, total, path)
   if not self.enabled or total == 0 then return end
   local percent = math.floor(done * 100 / total)
   if self.live then
      -- Not on every file: a tree of tens of thousands of tiny files would
      -- spend its time drawing.
      local every = math.max(1, math.floor(total / 200))
      if done ~= 1 and done ~= total and done % every ~= 0 then return end
      self.frame = self.frame % #SPINNER + 1
      io.stderr:write("\r\27[K", self.paint.cyan(SPINNER[self.frame]),
         (" analyzing %d/%d %s %d%%  "):format(done, total, term.bar(done / total, 20), percent),
         self.paint.dim(tail(path, 40)))
      self.line_open = true
   else
      local step = math.floor(percent / 10)
      if done ~= total and step == self.last_step then return end
      self.last_step = step
      io.stderr:write(self.paint.dim("lua-doctor:"),
         (" analyzing %d/%d files (%d%%)\n"):format(done, total, percent))
   end
end

--- The scan is over.
function Progress:finish(count)
   if not self.enabled then return end
   self:clear()
   if self.live then
      io.stderr:write(self.paint.green("✔"),
         (" Scanned %d file%s in %ds\n")
         :format(count, count == 1 and "" or "s", os.time() - self.started))
   else
      io.stderr:write(self.paint.dim("lua-doctor:"),
         (" Scanned %d file%s in %ds\n")
         :format(count, count == 1 and "" or "s", os.time() - self.started))
   end
end

return progress
