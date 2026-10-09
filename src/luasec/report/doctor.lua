-- The digest a person reads on a terminal: a header with the score, the counts,
-- and the findings grouped by code, worst first, a few locations each. It is a
-- view of the same findings the flat report lists; pipes and files still get the
-- list, so nothing a tool parses changes.
local categories = require "luasec.rules.categories"
local codes = require "luasec.rules.codes"
local score = require "luasec.report.score"
local summary = require "luasec.report.summary"
local term = require "luasec.cli.term"
local sanitize = require("luasec.util.util").sanitize

local doctor = {}

local TOP_GROUPS, TOP_LOCATIONS = 6, 3
local RANK = {critical = 4, high = 3, medium = 2, low = 1}
local SEVERITIES = {"critical", "high", "medium", "low"}

local function plural(count, word)
   return ("%d %s%s"):format(count, word, count == 1 and "" or "s")
end

-- One group per code, the worst first, then the biggest, then by code.
local function groups_of(list)
   local by_code, groups = {}, {}
   for _, finding in ipairs(list) do
      local group = by_code[finding.code]
      if not group then
         group = {code = finding.code, findings = {}, worst = 0, confidence = {}}
         by_code[finding.code] = group
         groups[#groups + 1] = group
      end
      group.findings[#group.findings + 1] = finding
      group.worst = math.max(group.worst, RANK[finding.severity] or 0)
      group.confidence[finding.confidence] = (group.confidence[finding.confidence] or 0) + 1
   end
   table.sort(groups, function(a, b)
      if a.worst ~= b.worst then return a.worst > b.worst end
      if #a.findings ~= #b.findings then return #a.findings > #b.findings end
      return a.code < b.code
   end)
   return groups
end

local function severity_name(group)
   for _, name in ipairs(SEVERITIES) do
      if RANK[name] == group.worst then return name end
   end
   return "low"
end

local function commonest(counts)
   local best, best_count = "", 0
   for name, count in pairs(counts) do
      if count > best_count or (count == best_count and name < best) then best, best_count = name, count end
   end
   return best
end

-- The score panel is a box 44 columns wide. Widths count characters, not
-- bytes, because the corners and the bar are multibyte.
local BOX_WIDTH, BAR_CELLS = 44, 20

local function pad(text, width)
   local len = utf8.len(text) or #text
   if len >= width then return text end
   return text .. string.rep(" ", width - len)
end

-- A line too long for the box keeps its head, with … marking the cut.
local function fit(text, width)
   if (utf8.len(text) or #text) <= width then return text end
   return text:sub(1, utf8.offset(text, width) - 1) .. "…"
end

--- Render a normalized findings list. `opts.paint` is a term palette, `opts.title`
-- names what was scanned, `opts.verbose` shows every code and every location.
function doctor.render(list, opts)
   opts = opts or {}
   local paint = opts.paint or term.palette(false)
   local result = score.summarize(list)
   local files, file_count = {}, 0
   for _, finding in ipairs(list) do
      if not files[finding.file] then files[finding.file] = true; file_count = file_count + 1 end
   end

   local out = {}
   local tone = ({good = paint.green, critical = paint.red})[result.label] or paint.yellow
   local label = result.label
   if result.coverage_gaps > 0 then label = label .. ", " .. plural(result.coverage_gaps, "coverage gap") end
   -- Only the label and the filled blocks carry colour. The padding is counted
   -- on the uncoloured text, so the box stays aligned with colour on or off.
   local head = " luasec"
   if opts.title then head = head .. "  " .. fit(sanitize(opts.title), BOX_WIDTH - 9) end
   local numbers = (" %d / 100  "):format(result.score)
   local numbers_len = utf8.len(numbers .. label) or #numbers
   local cells = math.max(0, math.min(BAR_CELLS, math.floor(result.score / 100 * BAR_CELLS + 0.5)))
   local filled, empty = string.rep("█", cells), string.rep("░", BAR_CELLS - cells)
   if cells > 0 then filled = tone(filled) end
   local counts = plural(#list, "finding") .. " in " .. plural(file_count, "file")
   if #list > 0 then counts = counts .. ": " .. summary.tally(list, "severity", SEVERITIES) end
   local families = {}
   for _, id in ipairs(categories.order()) do
      if result.categories[id] > 0 then families[#families + 1] = id .. " " .. result.categories[id] end
   end
   out[#out + 1] = "┌" .. string.rep("─", BOX_WIDTH) .. "┐"
   out[#out + 1] = "│" .. pad(head, BOX_WIDTH) .. "│"
   out[#out + 1] = "│" .. string.rep(" ", BOX_WIDTH) .. "│"
   out[#out + 1] = "│" .. numbers .. tone(label)
      .. string.rep(" ", BOX_WIDTH - numbers_len) .. "│"
   out[#out + 1] = "│ " .. filled .. empty
      .. string.rep(" ", BOX_WIDTH - 1 - BAR_CELLS) .. "│"
   out[#out + 1] = "│" .. string.rep(" ", BOX_WIDTH) .. "│"
   if #list == 0 then
      local clean = " ✔ No findings"
      out[#out + 1] = "│ " .. paint.green("✔ No findings")
         .. string.rep(" ", BOX_WIDTH - (utf8.len(clean) or #clean)) .. "│"
   else
      out[#out + 1] = "│" .. pad(fit(" " .. counts, BOX_WIDTH), BOX_WIDTH) .. "│"
      if #families > 0 then
         out[#out + 1] = "│" .. pad(fit(" " .. table.concat(families, " · "), BOX_WIDTH), BOX_WIDTH) .. "│"
      end
   end
   out[#out + 1] = "└" .. string.rep("─", BOX_WIDTH) .. "┘"

   if #list == 0 then
      return table.concat(out, "\n")
   end

   local groups = groups_of(list)
   local shown = opts.verbose and #groups or math.min(TOP_GROUPS, #groups)
   for index = 1, shown do
      local group = groups[index]
      local name = severity_name(group)
      local tint = ({critical = paint.red, high = paint.red, medium = paint.yellow})[name] or paint.dim
      local icon = ({critical = "✖", high = "✖", medium = "⚠"})[name] or "·"
      out[#out + 1] = ""
      out[#out + 1] = ("%s %s  %s%s  %s"):format(tint(icon), paint.bold(group.code), codes.meaning(group.code),
         #group.findings > 1 and (" ×" .. #group.findings) or "",
         paint.dim(name .. " · " .. commonest(group.confidence)))
      -- Two findings on one line are one place to look at, so a location is listed once.
      local seen, places = {}, {}
      for _, finding in ipairs(group.findings) do
         local place = ("%s:%d"):format(sanitize(finding.file), finding.line)
         if not seen[place] then
            seen[place] = true
            places[#places + 1] = place
         end
      end
      local limit = opts.verbose and #places or math.min(TOP_LOCATIONS, #places)
      for i = 1, limit do
         out[#out + 1] = "    " .. paint.dim(places[i])
      end
      if limit < #places then
         out[#out + 1] = "    " .. paint.dim(("… and %d more"):format(#places - limit))
      end
   end
   if shown < #groups then
      local hidden = 0
      for index = shown + 1, #groups do hidden = hidden + #groups[index].findings end
      out[#out + 1] = ""
      out[#out + 1] = paint.dim(("%s with %s hidden. luasec --verbose lists everything, --view list is the flat report.")
         :format(plural(#groups - shown, "more code"), plural(hidden, "finding")))
   end
   out[#out + 1] = ""
   out[#out + 1] = paint.dim("Next: luasec why <file>:<line>  ·  luasec rules explain <code>  ·  luasec fix <path>  ·  luasec --summary")
   return table.concat(out, "\n")
end

return doctor
