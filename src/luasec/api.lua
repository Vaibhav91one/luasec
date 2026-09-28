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
local platform_api = require "luasec.registry.platform_api"
local profiles = require "luasec.registry.profiles"
local rule_context = require "luasec.rules.context"
local rule_registry = require "luasec.rules.registry"
local inline_directives = require "luasec.engine.inline_directives"
local interprocedural = require "luasec.engine.interprocedural"
local rawscan = require "luasec.rules.rawscan"
local detect = require "luasec.bytecode.detect"
local bytecode_triage = require "luasec.bytecode.triage"

local api = {}

-- check_source takes a Lua string; the raw scan wants bytes, and the CLI reads
-- files as bytes, so keep the original string rather than the decoder object.
local function source_bytes_string(source)
   return type(source) == "string" and source or nil
end

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

--- Install the platform profiles and rule files named by `opts`.
-- Returns true, or nil plus a message when a profile or file is unusable.
local function install_registries(opts)
   platform_api.reset()

   if opts.std and opts.std ~= "" then
      local names, add = profiles.split(opts.std)
      if not add then
         -- Explicit list: the base Lua standard is still loaded, but no
         -- platform profile is implied.
      end
      for _, name in ipairs(names) do
         local declaration, err = profiles.load_builtin(name)
         if not declaration then return nil, err end
         platform_api.apply_profile(declaration)
      end
   end

   for _, path in ipairs(opts.rules or {}) do
      local declaration, err = profiles.load_file(path)
      if not declaration then return nil, err end
      platform_api.apply_profile(declaration)
   end

   for _, name in ipairs(opts.sources or {}) do
      platform_api.add_sources({{pattern = name, id = name, name = "declared source",
         confidence = opts.source_confidence or "high"}})
   end

   for _, name in ipairs(opts.sanitizers or {}) do
      platform_api.add_sanitizers("shell", {name})
   end

   return true
end

--- Load extra rule declarations from files, as an operator does with --rules.
function api.rules_load(paths)
   for _, path in ipairs(paths or {}) do
      local declaration, err = profiles.load_file(path)
      if not declaration then return nil, err end
      platform_api.apply_profile(declaration)
   end
   return true
end

--- Validate the platform profiles and rule files named by `opts`.
-- Returns true, or nil plus a message. Callers use this to fail before
-- analyzing anything.
function api.validate_options(opts)
   return install_registries(opts or {})
end

--- Analyze a single Lua source string.
-- Returns an array of findings, sorted by location.
function api.check_source(source, opts)
   opts = opts or {}
   local ok, install_error = install_registries(opts)
   if not ok then
      -- A profile or rule file we cannot load is an operator error, not a
      -- finding about the analyzed code. Fail loudly.
      error({luasec_config_error = true, message = install_error}, 0)
   end

   local chstate, syntax_error = parse_context.build(source, {max_nodes = opts.max_nodes})

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

      local results = {finding}

      -- A file that does not parse is exactly where an attacker would hide a
      -- payload, so the lexical scan still runs on the raw text. Without this,
      -- breaking the parser was a way to get a clean report.
      if not opts.no_raw_scan then
         local ok, raw = pcall(rawscan.scan_source, source_bytes_string(source), opts)
         if ok and type(raw) == "table" then
            for _, raw_finding in ipairs(raw) do
               if raw_finding.code ~= "901" then
                  results[#results + 1] = raw_finding
               end
            end
         end
      end

      return sort_findings(results)
   end

   local findings = taint_engine.run(chstate, opts)

   -- The cross-function and exposed-sink passes both visit every call site and
   -- every named function. On a file with tens of thousands of them that is
   -- minutes of work for a heuristic, so above this many lines they are skipped
   -- and 904 says so rather than the report quietly claiming a clean function.
   local expensive = #chstate.lines > (opts.max_function_lines or 4000)

   -- Taint across function boundaries, unless the file is too large for it.
   if chstate.resolved_locals ~= false and not opts.no_interprocedural and not expensive then
      local state = taint_engine.new_state()
      taint_engine.run(chstate, opts, state)
      local seen = {}
      for _, finding in ipairs(findings) do
         seen[table.concat({finding.code, tostring(finding.line), tostring(finding.column)}, "|")] = true
      end
      interprocedural.run(chstate, state, opts)
      for _, finding in ipairs(state.findings) do
         local key = table.concat({finding.code, tostring(finding.line), tostring(finding.column)}, "|")
         if not seen[key] then
            seen[key] = true
            findings[#findings + 1] = finding
         end
      end
   end

   -- Locations already explained by a stronger finding: a proven flow or an
   -- exposed sink. The shape-only finding at such a location says less, so it is
   -- dropped rather than reported twice.
   local covered = {}
   for _, finding in ipairs(findings) do
      if finding.code == "709" or finding.code == "710" or finding.code == "743" then
         covered[finding.line .. ":" .. finding.column] = true
      end
   end

   -- 708: an exported function whose execution sink nothing in this file feeds.
   -- The sink exists; the input lives somewhere we cannot see.
   if chstate.resolved_locals ~= false and not opts.no_interprocedural
         and opts.report_exposed_sinks ~= false and not expensive then
      local function sink_key(exposed)
         if not (exposed.sink_line and exposed.sink_offset) then return nil end
         local start = exposed.sink_offset - (chstate.line_offsets[exposed.sink_line] or 0) + 1
         return exposed.sink_line .. ":" .. math.max(1, start)
      end

      for _, exposed in ipairs(interprocedural.exposed_sinks(chstate, opts)) do
         local key = sink_key(exposed)
         if not (key and covered[key]) then
            if key then
               covered[key] = true
            end

            local spec = codes.get("708")
            -- 708 replaces the shape-only finding at this sink, so it carries
            -- that sink's severity rather than a lower one of its own.
            local sink_spec = codes.get(exposed.code)
            local finding = {
               code = "708",
               line = exposed.function_node.line or 1,
               column = math.max(1, exposed.function_node.offset or 1),
               end_column = math.max(1, exposed.function_node.offset or 1),
               severity = (sink_spec and sink_spec.severity) or spec.severity,
               confidence = "low",
               cwe = spec.cwe,
               name = exposed.name,
               sink = exposed.path,
               exposed_as = exposed.name,
            }
            finding.message = codes.render(spec, finding)
            findings[#findings + 1] = finding
         end
      end
   end

   local deduped = {}
   for _, finding in ipairs(findings) do
      local shape_only = finding.code == "701" or finding.code == "702"
         or finding.code == "703" or finding.code == "704"
      if not (shape_only and covered[finding.line .. ":" .. finding.column]) then
         deduped[#deduped + 1] = finding
      end
   end
   findings = deduped

   if expensive then
      findings[#findings + 1] = {
         code = "904", line = 1, column = 1, end_column = 1,
         severity = codes.get("904").severity, confidence = "certain",
         cwe = "CWE-0", name = "very large file",
         node_count = chstate.node_count, mode = "no cross-function analysis",
         message = codes.render(codes.get("904"), {name = "very large file"})
            .. "; cross-function and exposed-sink analysis were skipped",
      }
   end

   if chstate.resolved_locals == false then
      findings[#findings + 1] = {
         code = "904", line = 1, column = 1, end_column = 1,
         severity = codes.get("904").severity, confidence = "certain",
         cwe = "CWE-0", name = "large file",
         node_count = chstate.node_count, mode = "approximate",
         message = codes.render(codes.get("904"), {name = "large file"}),
      }
   end

   -- Rule modules see the same parsed program, after the dataflow pass.
   -- The decoder object is not a string, so `source_bytes` is what a snippet
   -- can actually be sliced out of.
   local ctx = rule_context.new(chstate, chstate.source_bytes, opts)
   for _, detector in ipairs(rule_registry.detectors()) do
      local ok, err = pcall(detector, ctx)
      if not ok then
         findings[#findings + 1] = {
            code = "901", line = 1, column = 1, end_column = 1,
            severity = "low", confidence = "certain",
            name = "rule module",
            message = "a rule failed to run: " .. tostring(err),
         }
      end
   end
   for _, finding in ipairs(ctx.findings) do
      findings[#findings + 1] = finding
   end

   sort_findings(findings)

   -- In-source directives are applied last, so `-- luasec: enable` can undo a
   -- config-level suppression.
   local directives, problems = inline_directives.parse(chstate)
   for _, problem in ipairs(problems) do
      findings[#findings + 1] = {
         code = "021", line = problem.line, column = 1, end_column = 1,
         severity = "low", confidence = "certain", name = "inline directive",
         message = problem.message,
      }
   end

   if #directives == 0 and #problems == 0 then
      return findings
   end

   local kept = {}
   for _, finding in ipairs(findings) do
      local applicable = {}
      for _, directive in ipairs(directives) do
         if directive.line <= finding.line then
            applicable[#applicable + 1] = directive
         end
      end
      if inline_directives.allows(applicable, finding, suppressed_by_options(opts, finding)) then
         kept[#kept + 1] = finding
      end
   end

   return kept
end

-- Mirrors the CLI's --ignore/--only/--enable so an in-source `enable` can
-- override them, which is the whole point of allowing directives at all.
function suppressed_by_options(opts, finding)
   local suppressed = false
   for _, pattern in ipairs(opts.ignore or {}) do
      if inline_directives.code_and_name_match(pattern, finding) then suppressed = true end
   end
   if opts.only then
      local matched = false
      for _, pattern in ipairs(opts.only) do
         if inline_directives.code_and_name_match(pattern, finding) then matched = true end
      end
      if not matched then suppressed = true end
   end
   return suppressed
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

-- Mirrors the CLI's --ignore/--only/--enable so an in-source `enable` can
-- override them, which is the whole point of allowing directives at all.
function suppressed_by_options(opts, finding)
   local suppressed = false
   for _, pattern in ipairs(opts.ignore or {}) do
      if inline_directives.code_and_name_match(pattern, finding) then suppressed = true end
   end
   if opts.only then
      local matched = false
      for _, pattern in ipairs(opts.only) do
         if inline_directives.code_and_name_match(pattern, finding) then matched = true end
      end
      if not matched then suppressed = true end
   end
   return suppressed
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
