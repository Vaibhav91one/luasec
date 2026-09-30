-- `luasec why <file>:<line>`: the findings on one line, how the data got there,
-- and how to fix it. It analyses the one file with the scan options given after
-- the target, so a finding that needs --std or --whole-program can be asked about.
local api = require "luasec.api"
local args = require "luasec.cli.args"
local findings = require "luasec.report.findings"
local plain = require "luasec.report.plain"

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

function why.run(argv, root, out, err)
   out, err = out or io.stdout, err or io.stderr
   local file, line = (argv[1] or ""):match("^(.+):(%d+)$")
   if not file then
      err:write("luasec: why needs <file>:<line>\n")
      return 2
   end
   local opts, parse_error = args.parse({table.unpack(argv, 2)})
   if not opts then
      err:write("luasec: " .. parse_error .. "\n")
      return 2
   end
   if #opts.paths > 0 then
      err:write("luasec: why takes one <file>:<line>, not more paths\n")
      return 2
   end
   local probe, open_error = io.open(file, "rb")
   if not probe then
      err:write(("luasec: cannot read %s: %s\n"):format(file, tostring(open_error)))
      return 2
   end
   probe:close()
   local ok, options_error = api.validate_options(opts)
   if not ok then
      err:write("luasec: " .. options_error .. "\n")
      return 2
   end

   local hits = {}
   for _, finding in ipairs(findings.normalize(api.analyze({file}, opts))) do
      if finding.line == tonumber(line) then hits[#hits + 1] = finding end
   end
   if #hits == 0 then
      out:write(("nothing reported at %s:%s\n"):format(file, line))
      return 0
   end

   for index, finding in ipairs(hits) do
      if index > 1 then out:write("\n") end
      out:write((plain.render({finding}):match("^[^\n]*")), "\n")
      if finding.trace then
         for _, step in ipairs(finding.trace) do
            out:write(("  %-6s  %s  %s:%d\n"):format(step.kind, step.name, step.file, step.line))
         end
      else
         out:write(NO_FLOW)
      end
      local fix = how_to_fix(root, finding.code)
      if fix then
         out:write("  how to fix:\n")
         for text in (fix .. "\n"):gmatch("([^\n]*)\n") do
            out:write(text == "" and "\n" or ("    " .. text .. "\n"))
         end
      end
      out:write("  more: luasec rules explain ", finding.code, "\n")
   end
   return 0
end

return why
