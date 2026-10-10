-- `lua-doctor why <file>:<line>`: the findings on one line, how the data got there,
-- and how to fix it. It analyses the one file with the scan options given after
-- the target, so a finding that needs --std or --whole-program can be asked about.
local api = require "luasec.api"
local args = require "luasec.cli.args"
local findings = require "luasec.report.findings"
local plain = require "luasec.report.plain"
local selection = require "luasec.cli.selection"
local config = require "luasec.cli.config"
local sanitize = require("luasec.util.util").sanitize

local why = {}

local NO_FLOW = "  no data flow: this code reports a shape, not a traced flow\n"

-- The "## How to fix" section of a code's doc page, or nil.
local function how_to_fix(root, code)
   local handle = io.open(root .. "/docs/rules/" .. code .. ".md", "rb")
   if not handle then return nil end
   local page = handle:read("*a")
   handle:close()
   local section = page:match("\n## How to fix\n(.-)\n## ") or page:match("\n## How to fix\n(.*)$")
   return section and section:gsub("^%s+", ""):gsub("%s+$", "")
end

-- A few lines of the file around `line`, the offending one marked with > and a
-- caret under its column, like a diff hunk. Tabs become one space so the caret
-- stays under the column lua-doctor reports. nil when the file cannot be read.
local function code_frame(file, line, column)
   local handle = io.open(file, "rb")
   if not handle then return nil end
   local lines = {}
   for text in handle:lines() do lines[#lines + 1] = sanitize((text:gsub("\t", " "))) end
   handle:close()
   if line < 1 or line > #lines then return nil end
   local first, last = math.max(1, line - 2), math.min(#lines, line + 2)
   local width = #tostring(last)
   local out = {}
   for number = first, last do
      out[#out + 1] = ("  %s %" .. width .. "d | %s"):format(number == line and ">" or " ", number, lines[number])
      if number == line then
         out[#out + 1] = ("    %s | %s^"):format(string.rep(" ", width), string.rep(" ", math.max(0, (column or 1) - 1)))
      end
   end
   return table.concat(out, "\n")
end

-- The lines `explain` prints, built first so the findings browser can reuse
-- the flow, the frame and the fix text without re-reading them.
function why.lines(finding, root)
   local lines = {}
   lines[#lines + 1] = (plain.render({finding}):match("^[^\n]*"))
   if finding.trace then
      for _, step in ipairs(finding.trace) do
         lines[#lines + 1] = sanitize(("  %-6s  %s  %s:%d"):format(step.kind, step.name, step.file, step.line))
      end
   else
      lines[#lines + 1] = NO_FLOW:gsub("\n$", "")
   end
   local frame = code_frame(finding.file, finding.line, finding.column)
   if frame then
      for text in (frame .. "\n"):gmatch("([^\n]*)\n") do
         lines[#lines + 1] = text
      end
   end
   local fix = how_to_fix(root, finding.code)
   if fix then
      lines[#lines + 1] = "  how to fix:"
      for text in (fix .. "\n"):gmatch("([^\n]*)\n") do
         lines[#lines + 1] = text == "" and "" or ("    " .. text)
      end
   end
   lines[#lines + 1] = "  more: lua-doctor rules explain " .. finding.code
   return lines
end

why.code_frame = code_frame
why.how_to_fix = how_to_fix

function why.explain(finding, root, out)
   out = out or io.stdout
   for _, line in ipairs(why.lines(finding, root)) do
      out:write(line, "\n")
   end
end

function why.run(argv, root, out, err)
   out, err = out or io.stdout, err or io.stderr
   local file, line = (argv[1] or ""):match("^(.+):(%d+)$")
   if not file then
      err:write("lua-doctor: why needs <file>:<line>\n")
      return 2
   end
   local opts, parse_error = args.parse({table.unpack(argv, 2)})
   if not opts then
      err:write("lua-doctor: " .. parse_error .. "\n")
      return 2
   end
   if #opts.paths > 0 then
      err:write("lua-doctor: why takes one <file>:<line>, not more paths\n")
      return 2
   end
   local probe, open_error = io.open(file, "rb")
   if not probe then
      err:write(("lua-doctor: cannot read %s: %s\n"):format(file, tostring(open_error)))
      return 2
   end
   probe:close()
   local settings, settings_error = selection.settings(opts)
   if not settings then
      err:write("lua-doctor: " .. settings_error .. "\n")
      return 2
   end
   local ok, options_error = api.validate_options(opts)
   if not ok then
      err:write("lua-doctor: " .. options_error .. "\n")
      return 2
   end

   local hits = {}
   local raw = api.analyze({file}, opts)
   selection.override(raw, settings)
   raw = config.apply_allow(selection.filter(raw, opts), settings.allow)
   for _, finding in ipairs(findings.normalize(raw)) do
      if finding.line == tonumber(line) then hits[#hits + 1] = finding end
   end
   if #hits == 0 then
      out:write(("nothing reported at %s:%s\n"):format(file, line))
      return 0
   end

   for index, finding in ipairs(hits) do
      if index > 1 then out:write("\n") end
      why.explain(finding, root, out)
   end
   return 0
end

return why
