-- Interactive menu after a terminal scan. Changes nothing about the scan:
-- it runs after the report is written and its result is ignored for the exit
-- code. Nothing is launched or written without the person choosing it.
local term = require "luasec.cli.term"
local why = require "luasec.cli.why_cmd"
local fix_cmd = require "luasec.cli.fix_cmd"
local ci_cmd = require "luasec.cli.ci_cmd"
local install_cmd = require "luasec.cli.install_cmd"
local review = require "luasec.cli.review"
local plain = require "luasec.report.plain"
local render = require "luasec.report.render"
local codes = require "luasec.rules.codes"

local menu = {}

local KEYS = {"r", "e", "f", "a", "s", "b", "c", "i", "q"}
local LABELS = {
   r = "review findings",
   e = "explain a finding",
   f = "fix with an AI agent",
   a = "show every finding",
   s = "save a report",
   b = "save a baseline",
   c = "set up CI",
   i = "install agent guidance",
   q = "quit",
}

-- Single-key mode also switches off the signal keys (-isig), so Ctrl-C arrives as a
-- byte the menu reads as "quit" and can restore the terminal, instead of a signal
-- that kills the process with echo still off.
local STTY_RAW = "stty -icanon -echo -isig min 1"
local STTY_COOKED = "stty icanon echo isig"

function menu.wanted(opts, list, format)
   if opts.no_interactive then return false end
   if opts.output or opts.summary or opts.score or opts.quiet or opts.baseline then
      return false
   end
   if format ~= "plain" then return false end
   if #list == 0 then return false end
   if opts.interactive then return true end
   return term.is_tty(0) and term.is_tty(1)
end

local function flush(out)
   if out.flush then out:flush() end
end

local function show(context, mark)
   local out = context.out
   out:write("What next?\n")
   for index, key in ipairs(KEYS) do
      out:write(((index == mark) and "> " or "  ") .. key .. "  " .. LABELS[key] .. "\n")
   end
   flush(out)
end

local function redraw(context, mark)
   local out = context.out
   out:write(("\27[%dA"):format(#KEYS + 1))
   out:write("\27[KWhat next?\n")
   for index, key in ipairs(KEYS) do
      out:write("\27[K" .. ((index == mark) and "> " or "  ") .. key .. "  " .. LABELS[key] .. "\n")
   end
   flush(out)
end

-- luasec: ignore 708  the stty commands are constant mode switches, never user input
local function read_line(context, tty, prompt)
   context.out:write(prompt)
   flush(context.out)
   if tty then os.execute(STTY_COOKED) end
   local line = io.read("*l")
   if tty then os.execute(STTY_RAW) end
   return line
end

local function trim(text)
   return text:match("^%s*(.-)%s*$")
end

local function sorted_findings(list)
   local copy = {}
   for _, finding in ipairs(list) do copy[#copy + 1] = finding end
   table.sort(copy, function(left, right)
      local lrank, rrank = plain.severity_rank(left.severity), plain.severity_rank(right.severity)
      if lrank ~= rrank then return lrank > rrank end
      if left.file ~= right.file then return left.file < right.file end
      return (left.line or 0) < (right.line or 0)
   end)
   return copy
end

local function do_explain(list, context, tty)
   local ordered = sorted_findings(list)
   local count = math.min(15, #ordered)
   for index = 1, count do
      local finding = ordered[index]
      context.out:write(("  %d  %s  %s:%d  %s\n"):format(
         index, finding.code, finding.file, finding.line, codes.meaning(finding.code)))
   end
   local answer = read_line(context, tty, ("Which finding? [1-%d]: "):format(count))
   if answer == nil then return end
   local pick = tonumber(trim(answer):match("^(%d+)$"))
   if not pick or pick < 1 or pick > count then return end
   why.explain(ordered[pick], context.root, context.out)
end

local function do_fix(list, context, tty)
   local agent = read_line(context, tty, "Agent [claude/codex/cursor] (claude): ")
   if agent == nil then return end
   agent = trim(agent)
   if agent == "" then agent = "claude" end
   local skip = read_line(context, tty, "Skip the agent's approval prompts? [y/N]: ")
   if skip == nil then return end
   local launch = read_line(context, tty, "Launch the agent, or just print the prompt? [launch/print] (print): ")
   if launch == nil then return end
   local fargv = {"--agent", agent}
   if trim(skip) ~= "y" then fargv[#fargv + 1] = "--safe" end
   if trim(launch) ~= "launch" then fargv[#fargv + 1] = "--print" end
   for _, token in ipairs(context.argv) do fargv[#fargv + 1] = token end
   fix_cmd.run(fargv, context.root, context.out, context.err)
end

local function do_all(list, context)
   context.out:write(plain.render(list), "\n")
end

local function do_save(list, context, tty)
   local fmt = read_line(context, tty, "Format [json/sarif/html] (json): ")
   if fmt == nil then return end
   fmt = trim(fmt)
   if fmt == "" then fmt = "json" end
   if fmt ~= "json" and fmt ~= "sarif" and fmt ~= "html" then
      context.out:write(("unknown format '%s': expected json, sarif or html\n"):format(fmt))
      return
   end
   local file = read_line(context, tty, ("File (luasec-report.%s): "):format(fmt))
   if file == nil then return end
   file = trim(file)
   if file == "" then file = "luasec-report." .. fmt end
   local text, render_error = render.render(list, fmt)
   if not text then
      context.out:write("luasec: " .. tostring(render_error) .. "\n")
      return
   end
   local handle, open_error = io.open(file, "wb")
   if not handle then
      context.out:write("luasec: cannot write " .. file .. ": " .. tostring(open_error) .. "\n")
      return
   end
   handle:write(text, "\n")
   handle:close()
   context.out:write("wrote " .. file .. "\n")
end

local function do_baseline(list, context, tty)
   local file = read_line(context, tty, "File (luasec-baseline.json): ")
   if file == nil then return end
   file = trim(file)
   if file == "" then file = "luasec-baseline.json" end
   local text = render.render(list, "json")
   local handle, open_error = io.open(file, "wb")
   if not handle then
      context.out:write("luasec: cannot write " .. file .. ": " .. tostring(open_error) .. "\n")
      return
   end
   handle:write(text, "\n")
   handle:close()
   context.out:write("wrote " .. file .. "; use luasec --baseline " .. file .. " next time\n")
end

local function do_ci(list, context)
   ci_cmd.run({"install"}, context.root, context.out, context.err)
end

local function do_install(list, context)
   install_cmd.run({}, context.root, context.out, context.err)
end

local function do_review(list, context)
   review.run(list, context)
end

local ACTIONS = {
   r = do_review,
   e = do_explain,
   f = do_fix,
   a = do_all,
   s = do_save,
   b = do_baseline,
   c = do_ci,
   i = do_install,
}

local function read_key()
   local first = io.read(1)
   if first == nil then return "quit" end
   if first == "\4" or first == "\3" then return "quit" end
   if first == "\27" then
      local second = io.read(1)
      if second == nil then return "quit" end
      if second ~= "[" then return "quit" end
      local third = io.read(1)
      if third == nil then return "quit" end
      if third == "A" then return "up" end
      if third == "B" then return "down" end
      return "ignore"
   end
   if first == "\r" or first == "\n" then return "enter" end
   return first
end

function menu.run(list, context)
   context.out = context.out or io.stdout
   context.err = context.err or io.stderr
   local tty = term.is_tty(0)
   -- luasec: ignore 708  the stty command is a constant mode switch, never user input
   if tty then os.execute(STTY_RAW) end
   local function loop()
      local mark = 1
      show(context, mark)
      while true do
         local key = read_key()
         if key == "quit" then
            break
         elseif key == "up" then
            mark = mark - 1
            if mark < 1 then mark = #KEYS end
            if tty then redraw(context, mark) end
         elseif key == "down" then
            mark = mark + 1
            if mark > #KEYS then mark = 1 end
            if tty then redraw(context, mark) end
         elseif key == "enter" then
            local picked = KEYS[mark]
            if picked == "q" then break end
            ACTIONS[picked](list, context, tty)
            show(context, mark)
         elseif key == "ignore" then
            -- unknown escape: stay on the menu
         elseif ACTIONS[key] then
            if key == "q" then break end
            for index, name in ipairs(KEYS) do
               if name == key then mark = index end
            end
            ACTIONS[key](list, context, tty)
            show(context, mark)
         end
      end
   end
   -- An error inside an action must never leave the terminal in single-key mode.
   local ok, failure = pcall(loop)
   -- luasec: ignore 708  the stty command is a constant mode switch, never user input
   if tty then os.execute(STTY_COOKED) end
   if not ok then context.err:write("luasec: the menu stopped: " .. tostring(failure) .. "\n") end
end

return menu
