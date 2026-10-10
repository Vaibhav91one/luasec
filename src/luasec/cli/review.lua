-- Findings browser: a cursor list plus a detail pane, reachable from the
-- terminal menu. The model is pure, so it is tested without a terminal; run
-- is a thin shell over it that reuses the menu's raw-mode handling.
local categories = require "luasec.rules.categories"
local codes = require "luasec.rules.codes"
local plain = require "luasec.report.plain"
local term = require "luasec.cli.term"
local why = require "luasec.cli.why_cmd"

local review = {}

-- How many list rows the top window shows; the window scrolls around the cursor.
local LIST_ROWS = 8

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

--- The browser model for a findings list: rows grouped by category in
-- categories.order(), worst first inside each group, with a header row per
-- group. `cursors` holds the row indices of the finding rows, so the headers
-- are shown but never selected.
function review.model(list)
   local by_category = {}
   for _, finding in ipairs(sorted_findings(list)) do
      local id = categories.of(finding.code) or "meta"
      by_category[id] = by_category[id] or {}
      by_category[id][#by_category[id] + 1] = finding
   end
   local rows, cursors = {}, {}
   for _, id in ipairs(categories.order()) do
      local group = by_category[id]
      if group and #group > 0 then
         rows[#rows + 1] = {kind = "header", label = categories.title(id), count = #group, category = id}
         for _, finding in ipairs(group) do
            rows[#rows + 1] = {kind = "finding", finding = finding}
            cursors[#cursors + 1] = #rows
         end
      end
   end
   return {rows = rows, cursors = cursors}
end

local function header_text(row)
   return ("-- %s (%d)"):format(row.label, row.count)
end

-- A finding row from its parts: marker + code + place + message. The place
-- (file:line) has priority and is fitted with fit_path, so its tail always
-- survives; the message is added only when at least 12 columns remain for
-- it, fitted to what remains, else dropped.
local function finding_row(finding, mark, width)
   local head = mark .. finding.code
   local place = term.fit_path(finding.file .. ":" .. finding.line, width - #head - 2)
   local line = head .. "  " .. place
   local rest = width - term.len(line) - 2
   if rest >= 12 then
      line = line .. "  " .. term.fit(codes.meaning(finding.code), rest)
   end
   return line
end

--- The detail pane for one finding, as a list of lines: the title, the
-- location with its severity and confidence, the Why section with the
-- message and, for a traced flow, the source-to-sink steps, the Evidence
-- section with the code frame, the Fix section with the rule's fix text,
-- and the refs.
function review.detail(finding, root)
   local lines = {}
   lines[#lines + 1] = finding.code .. "  " .. codes.meaning(finding.code)
   lines[#lines + 1] = ("%s:%d  %s · %s"):format(finding.file, finding.line, finding.severity, finding.confidence)
   lines[#lines + 1] = ""
   lines[#lines + 1] = "Why"
   lines[#lines + 1] = "  " .. (finding.message or "")
   if finding.trace then
      local names = {}
      for _, step in ipairs(finding.trace) do
         local name = step.name or (step.kind == "sink" and finding.sink) or ""
         if name ~= "" then names[#names + 1] = name end
      end
      lines[#lines + 1] = "  " .. table.concat(names, " → ")
      for _, step in ipairs(finding.trace) do
         local name = step.name or (step.kind == "sink" and finding.sink) or ""
         lines[#lines + 1] = ("  %-6s  %s  %s:%d"):format(
            step.kind, name, step.file or finding.file, step.line)
      end
   end
   lines[#lines + 1] = ""
   lines[#lines + 1] = "Evidence"
   local frame = why.code_frame(finding.file, finding.line, finding.column)
   if frame then
      for text in (frame .. "\n"):gmatch("([^\n]*)\n") do
         lines[#lines + 1] = text
      end
   end
   lines[#lines + 1] = ""
   lines[#lines + 1] = "Fix"
   local fix = why.how_to_fix(root, finding.code)
   if fix then
      for text in (fix .. "\n"):gmatch("([^\n]*)\n") do
         lines[#lines + 1] = text == "" and "" or ("  " .. text)
      end
   end
   lines[#lines + 1] = ""
   lines[#lines + 1] = "  more: lua-doctor rules explain " .. finding.code
   lines[#lines + 1] = "  ref: docs/rules/" .. finding.code .. ".md"
   return lines
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
      if third == "C" then return "right" end
      if third == "D" then return "left" end
      return "ignore"
   end
   if first == "\r" or first == "\n" then return "enter" end
   if first == "k" then return "up" end
   if first == "j" then return "down" end
   if first == "q" then return "q" end
   return first
end

local function flush(out)
   if out.flush then out:flush() end
end

-- The list window, scrolled so the selected row is always shown, then a rule
-- line and the detail of the selected finding. Every line is fitted to the
-- width minus 1 (the last column auto-wraps on many terminals); list rows are
-- fitted, detail body text is wrapped, so no physical line exceeds the width.
local function draw_list(context, model, selected)
   local out = context.out
   -- Read once per screen draw (cheap enough); cached nowhere so a resize is
   -- seen on the next draw.
   local width = math.max(1, term.width() - 1)
   local current = model.cursors[selected]
   local first = math.max(1, math.min(current - 3, math.max(1, #model.rows - LIST_ROWS + 1)))
   local last = math.min(#model.rows, first + LIST_ROWS - 1)
   for index = first, last do
      local row = model.rows[index]
      if row.kind == "header" then
         out:write(term.fit("  " .. header_text(row), width) .. "\n")
      else
         out:write(finding_row(row.finding, (index == current) and "> " or "  ", width) .. "\n")
      end
   end
   out:write("---\n")
   for _, line in ipairs(review.detail(model.rows[current].finding, context.root)) do
      for _, piece in ipairs(term.wrap(line, width)) do
         out:write(piece, "\n")
      end
   end
   flush(out)
end

local function draw_full(context, model, selected)
   local out = context.out
   local width = math.max(1, term.width() - 1)
   local row = model.rows[model.cursors[selected]]
   for _, line in ipairs(review.detail(row.finding, context.root)) do
      for _, piece in ipairs(term.wrap(line, width)) do
         out:write(piece, "\n")
      end
   end
   flush(out)
end

--- Browse a findings list. Up/Down (k/j) move over findings only; Enter or
-- Right shows the detail full-screen until Esc/Left/q; Esc or q leaves the
-- browser. Ctrl-C/Ctrl-D leave too, and a closed stdin quits.
function review.run(list, context)
   context.out = context.out or io.stdout
   context.err = context.err or io.stderr
   if #list == 0 then return end
   local model = review.model(list)
   if #model.cursors == 0 then return end
   local tty = term.is_tty(0)
   -- lua-doctor: ignore 708  the stty command is a constant mode switch, never user input
   if tty then term.raw() end
   local function loop()
      local selected, full = 1, false
      context.out:write("\27[H\27[J")
      draw_list(context, model, selected)
      while true do
         local key = read_key()
         if key == "quit" then
            break
         elseif key == "up" then
            if not full then
               selected = math.max(1, selected - 1)
               context.out:write("\27[H\27[J")
               draw_list(context, model, selected)
            end
         elseif key == "down" then
            if not full then
               selected = math.min(#model.cursors, selected + 1)
               context.out:write("\27[H\27[J")
               draw_list(context, model, selected)
            end
         elseif key == "enter" or key == "right" then
            if not full then
               full = true
               context.out:write("\27[H\27[J")
               draw_full(context, model, selected)
            end
         elseif key == "escape" or key == "left" or key == "q" then
            if full then
               full = false
               context.out:write("\27[H\27[J")
               draw_list(context, model, selected)
            else
               break
            end
         elseif key == "ignore" then
            -- unknown escape: stay where we are
         end
      end
   end
   -- An error inside the loop must never leave the terminal in single-key mode.
   local ok, failure = pcall(loop)
   -- lua-doctor: ignore 708  the stty command is a constant mode switch, never user input
   if tty then term.cooked() end
   if not ok then context.err:write("lua-doctor: the browser stopped: " .. tostring(failure) .. "\n") end
end

return review
