-- Report rendering dispatch. Selects the formatter for a given format name and
-- runs it from the contract, so every format sees the same findings in the same
-- order: plain, json, sarif and html cannot drift apart.
--
-- A name this module does not know is rejected with the same message the CLI
-- uses, so a typo reads the same whether it reaches the library or the command
-- line. `list` is rendered as given: callers that have a raw findings list
-- normalize it themselves (as `findings.normalize` is the contract boundary),
-- and a baseline run passes a list whose per-finding status must be preserved,
-- which re-normalizing would drop.
local json = require "luadoctor.report.json"
local plain = require "luadoctor.report.plain"
local sarif = require "luadoctor.report.sarif"
local html = require "luadoctor.report.html"
local findings = require "luadoctor.report.findings"

local render = {}

local UNKNOWN_FORMAT = "unknown format '%s': expected plain, json, sarif or html"

--- Render a normalized findings list in the named format.
-- Returns the rendered report, or nil plus a message when `name` is not a
-- format this tool knows.
function render.render(list, name, opts)
   if name == "json" then
      return json.encode(findings.document(list, {exit_code = opts and opts.exit_code,
         baseline = opts and opts.baseline_counts}))
   elseif name == "sarif" then
      return sarif.render(list, opts)
   elseif name == "html" then
      return html.render(list, opts)
   elseif name == "plain" then
      return plain.render(list, opts)
   end
   return nil, UNKNOWN_FORMAT:format(name)
end

return render
