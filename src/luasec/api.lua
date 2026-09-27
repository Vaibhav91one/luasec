-- Public entry points. Tests and callers use only this module.
--
--   check_source(src, opts)      analyze one Lua string, return a report (findings)
--   analyze(paths, opts)         analyze files, return a report
--   format(report, name)         render a report
--   rules.load(path)             load a custom rules file
--   validate_payload(src, opts)  run the payload validator, return a verdict
local parse_context = require "luasec.engine.parse_context"
local taint_engine = require "luasec.engine.taint"
local codes = require "luasec.rules.codes"
local detect = require "luasec.bytecode.detect"
local bytecode_triage = require "luasec.bytecode.triage"

local api = {}

local function sort_findings(findings)
   table.sort(findings, function(a, b)
      if a.line ~= b.line then return (a.line or 0) < (b.line or 0) end
      if a.column ~= b.column then return (a.column or 0) < (b.column or 0) end
      return tostring(a.code) < tostring(b.code)
   end)
   return findings
end

--- The rule catalogue: every warning code with its severity, confidence and CWE.
-- Callers use this to build documentation, editor integrations and dashboards.
function api.rule_catalogue()
   local catalogue = {}
   for _, spec in ipairs(codes.all()) do
      catalogue[#catalogue + 1] = {
         code = spec.code,
         severity = spec.severity,
         confidence = spec.confidence,
         cwe = spec.cwe,
         message = spec.message,
         fields = spec.fields,
      }
   end
   return catalogue
end

--- Analyze a single Lua source string.
-- Returns an array of findings, sorted by location.
function api.check_source(source, opts)
   opts = opts or {}
   local chstate, syntax_error = parse_context.build(source)

   if not chstate then
      local finding = {
         code = "901",
         line = (syntax_error and syntax_error.line) or 1,
         column = 1,
         end_column = 1,
         severity = "low",
         confidence = "certain",
         name = "parse error",
      }
      finding.message = codes.render(codes.get("901"), finding)
      if syntax_error and syntax_error.msg then
         finding.message = finding.message .. ": " .. tostring(syntax_error.msg)
      end
      return {finding}
   end

   local findings = taint_engine.run(chstate, opts)
   return sort_findings(findings)
end

--- Analyze files. `paths` is an array of file paths.
function api.analyze(paths, opts)
   opts = opts or {}
   local findings = {}
   local files = {}

   for _, path in ipairs(paths) do
      local handle, open_err = io.open(path, "rb")
      if not handle then
         findings[#findings + 1] = {
            code = "901", line = 1, column = 1, end_column = 1,
            severity = "low", confidence = "certain",
            name = path, file = path,
            message = "cannot read file: " .. tostring(open_err),
         }
      else
         local source = handle:read("*a")
         handle:close()
         files[#files + 1] = {path = path, source = source}
      end
   end

   for _, file in ipairs(files) do
      -- A precompiled chunk is triaged, not parsed: there is no source for the
      -- taint engine to work on, and feeding it bytes only produces a 901.
      local per_file
      if detect.is_bytecode(file.source) then
         per_file = bytecode_triage.triage(file.source, opts)
      else
         per_file = api.check_source(file.source, opts)
      end
      for _, finding in ipairs(per_file) do
         finding.file = file.path
         findings[#findings + 1] = finding
      end
   end

   return sort_findings(findings)
end

--- Decide whether a Lua payload actually achieves execution.
--
-- The payload is untrusted, so it is never run here: it is handed to a child
-- interpreter with `os` and `io` replaced by recorders and bounded by an
-- instruction count, a memory ceiling, a load depth and a wall clock. Returns a
-- verdict table:
--
--   verdict          "rce" | "partial" | "benign" | "timeout" | "error".
--                    "timeout" means a bound stopped it, which is any of the
--                    four above, not only the clock.
--   sinks_reached    array of {name, kind, line, source, arg} for every capability
--                    the payload reached and the sandbox refused
--   escape_attempts  the subset of those that tried to leave the sandbox
--   payload_chain    the steps the payload took, in order, deduplicated
--   exit_reason      why the run ended
--   reason_source    "sandbox" or "payload": whose words exit_reason is. It is the
--                    payload's whenever the payload raised the error itself.
--   payload_result   what the payload returned, if it was a scalar
--   payload_output   what the payload printed or wrote, including through
--                    `io.stdout` and `io.stderr`
--   source           the source name the verdict is traced back to, and the one
--                    every reported line number is counted in
--   lua              the dialect the payload was validated under
--   interpreter      the interpreter binary that was run
--   duration_ms      CPU time the payload burned in the child
--
-- Everything named `payload_*`, plus `exit_reason` when `reason_source` is
-- "payload" and the `arg` of a sink, is text the payload chose. A caller that
-- shows any of it to a person should mark it the way `luasec --validate` does.
--
-- Options: `timeout_ms`, `max_instructions`, `max_memory_kb`, `max_load_depth`,
-- `max_source_bytes`, `name` (the source name to trace the verdict to) and `lua`
-- (the interpreter to run the payload with; defaults to $LUASEC_LUA, then
-- $LUA_BIN, then `lua` on PATH).
function api.validate_payload(source, opts)
   return require("luasec.validate.driver").run(source, opts or {})
end

return api
