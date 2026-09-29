-- Public entry points. Tests and callers use only this module.
--
--   check_source(src, opts)      analyze one Lua string, return a report (findings)
--   analyze(paths, opts)         analyze files, return a report
--   format(report, name, opts)   render a report
--   rules_load(paths)            load custom rules files
--   validate_payload(src, opts)  run the payload validator, return a verdict
local codes = require "luasec.rules.codes"
local platform_api = require "luasec.registry.platform_api"
local profiles = require "luasec.registry.profiles"
local inline_directives = require "luasec.engine.inline_directives"
local detect = require "luasec.bytecode.detect"
local bytecode_triage = require "luasec.bytecode.triage"
local render = require "luasec.report.render"
local report_contract = require "luasec.report.findings"
local pipeline = require "luasec.engine.pipeline"

local api = {}



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


-- The options that are lists, and what a list means for each. A list is a table
-- with a contiguous array part, and saying so is the whole point of checking
-- them: `ipairs` over a bare string runs zero times and returns nothing, so
-- `rules = "vendor.lua"` loaded no profile at all and `only = "709"` selected
-- nothing, both of which report as a clean run of a narrower analysis than the
-- caller asked for. The name is the flag where the CLI has one and the key where
-- it does not, so the message names what the reader actually wrote.
local LIST_OPTIONS = {
   {name = "--rules", key = "rules", expected = "a list of profile file paths"},
   {name = "--only", key = "only", expected = "a list of code patterns"},
   {name = "--ignore", key = "ignore", expected = "a list of code patterns"},
   {name = "--enable", key = "enable", expected = "a list of code patterns"},
   {name = "sources", key = "sources", expected = "a list of API paths"},
   {name = "sanitizers", key = "sanitizers", expected = "a list of sanitizer names"},
}

-- The numeric bounds. `tonumber` rather than a type check, and deliberately: the
-- CLI's own parser stores every numeric flag as the string it was typed as and
-- hands that straight to api, so "1000" is the shape main.lua passes on. The
-- wording is main.lua's, unchanged, so the same defect reads the same whichever
-- of the two caught it.
local NUMBER_OPTIONS = {
   {name = "--jobs", key = "jobs"},
   {name = "--max-nodes", key = "max_nodes"},
   {name = "--validate-timeout", key = "validate_timeout"},
   {name = "max_function_lines", key = "max_function_lines"},
}

--- The options table, checked before anything reads it.
--
-- This is the library's own gate. The CLI validates its flags in main.lua and
-- never reaches the analysis with a bad one, so every check here only ever fires
-- for a caller using the library, which is the caller with nothing between
-- their typo and a traceback. None of these values were checked there at all:
-- `profiles.split` called `:match` on a `std` that arrived as a table and
-- raised `attempt to call a nil value (method 'match')` straight out of
-- `check_source`, a `rules` entry that was not a string reached `loadfile`, and
-- a list option given as a bare string made `ipairs` run zero times, so the
-- option was silently ignored and the run came back narrower than it was asked
-- for.
--
-- One function, reached from `validate_options` and from every entry point that
-- builds its own options: which function a caller happens to reach for must not
-- decide whether their configuration is checked.
local function validate_config(opts)
   if opts == nil then return true end
   if type(opts) ~= "table" then
      return nil, ("options must be a table, got %s"):format(type(opts))
   end

   -- Split on "+" with a Lua pattern, so this has to be a string before anything
   -- looks at it. A table is the natural shape when options are built from a
   -- config file or JSON, and not one the command line can produce.
   if opts.std ~= nil and type(opts.std) ~= "string" then
      return nil, ("--std needs a string like '+openwrt+luci', got %s")
         :format(type(opts.std))
   end

   for _, option in ipairs(LIST_OPTIONS) do
      local value = opts[option.key]
      if value ~= nil then
         if type(value) ~= "table" then
            return nil, ("%s needs %s, got %s"):format(option.name, option.expected,
               type(value))
         end
         for _, entry in ipairs(value) do
            if type(entry) ~= "string" then
               return nil, ("every %s entry must be a string, got %s")
                  :format(option.name, type(entry))
            end
         end
      end
   end

   for _, option in ipairs(NUMBER_OPTIONS) do
      local raw = opts[option.key]
      if raw ~= nil then
         local value = tonumber(raw)
         -- An integer, because the message says so and a fractional node cap is
         -- a half-node cap, which is not a thing. The same test main.lua makes.
         if not value or value < 1 or value % 1 ~= 0 then
            return nil, ("%s needs a positive integer"):format(option.name)
         end
      end
   end

   -- Severity and confidence values name a rank the analyzer looks up in a table
   -- keyed by word: a typo like "crtical" was not a key, so the lookup fell to 0
   -- and every finding sat above it. The threshold silently did nothing, the
   -- confidence filter let everything through, and --fail-on handed CI a green
   -- build for a file full of criticals. All three are configuration, so a bad
   -- word is a config error -- the operator needs to know before any analysis.
   local SEVERITY_VALUES = {critical = true, high = true, medium = true, low = true}
   local CONFIDENCE_VALUES = {certain = true, high = true, medium = true, low = true}

   for _, option in ipairs({
      {key = "severity_threshold", flag = "--severity-threshold", valid = SEVERITY_VALUES},
      {key = "fail_on", flag = "--fail-on", valid = SEVERITY_VALUES},
      {key = "min_confidence", flag = "--min-confidence", valid = CONFIDENCE_VALUES},
   }) do
      local value = opts[option.key]
      if value ~= nil then
         if type(value) ~= "string" or not option.valid[value] then
            local valid = option.flag == "--min-confidence"
               and "certain, high, medium, low"
               or "critical, high, medium, low"
            return nil, ("%s needs one of %s, got %s"):format(option.flag, valid,
               type(value) == "string" and value or type(value))
         end
      end
   end

   -- Carried on every declared source and reported as the confidence of anything
   -- it reaches, and read as a pattern on the way: 42 here reached the wildcard
   -- matcher as a nil pattern.
   if opts.source_confidence ~= nil and type(opts.source_confidence) ~= "string" then
      return nil, ("source_confidence needs a string, got %s")
         :format(type(opts.source_confidence))
   end

   return true
end


--- `opts` as the analysis will use it, or the config error raised. The entry
-- points that build their own options go through here, so a caller cannot skip
-- the check by calling `check_source` instead of `validate_options`.
local function checked_options(opts)
   local ok, message = validate_config(opts)
   if not ok then pipeline.raise_config_error(message) end
   return opts or {}
end

--- The source string, or the config error. The decoder wants a string and is
-- called on the very next line, so a nil or a table reached it and raised from
-- inside luacheck, and a number was reported instead as a 901 "source could not
-- be parsed" - a finding about the analyzed code, produced by a mistake in the
-- caller's own arguments.
local function checked_source(source)
   if type(source) ~= "string" then
      pipeline.raise_config_error(("source must be a string of Lua, got %s"):format(type(source)))
   end
   return source
end

--- The path list, or the config error. `ipairs` over a string yields nothing at
-- all, so a single path handed to `analyze` analyzed zero files and returned an
-- empty report: for a tool whose empty report means "looked at it and found
-- nothing", that is the most misleading way this call can be got wrong.
local function checked_paths(paths)
   if type(paths) ~= "table" then
      pipeline.raise_config_error(("paths must be a list of file paths, got %s"):format(type(paths)))
   end
   for _, path in ipairs(paths) do
      if type(path) ~= "string" then
         pipeline.raise_config_error(("every path must be a string, got %s"):format(type(path)))
      end
   end
   return paths
end

--- Load extra rule declarations from files, as an operator does with --rules.
function api.rules_load(paths)
   -- The same check `validate_options` makes of --rules, on the same value, so
   -- there is one rule and not two: `rules_load("vendor.lua")` ran ipairs over a
   -- string, which yields nothing, and returned true having loaded nothing.
   local ok, message = validate_config({rules = paths})
   if not ok then return ok, message end
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
local function validate_filter_patterns(opts)
   for _, flag in ipairs({"only", "ignore", "enable"}) do
      for _, pattern in ipairs(opts[flag] or {}) do
         local code_half, name_half = pattern:match("^([^:]*):(.*)$")
         if not code_half then code_half, name_half = pattern, nil end
         if not inline_directives.is_readable_pattern(code_half) then
            return nil, ("--%s pattern %q is not a code pattern"):format(flag, pattern)
         end
         if name_half ~= nil and name_half ~= ""
            and not inline_directives.is_readable_pattern(name_half) then
            return nil, ("--%s pattern %q has a name half that is not a pattern")
               :format(flag, pattern)
         end
      end
   end
   return true
end

function api.validate_options(opts)
   local ok, err = validate_config(opts)
   if not ok then return ok, err end
   ok, err = pipeline.install_registries(opts or {})
   if not ok then return ok, err end
   return validate_filter_patterns(opts or {})
end




--- Analyze a single Lua source string.
-- Returns an array of findings, sorted by location.
function api.check_source(source, opts)
   opts = checked_options(opts)
   source = checked_source(source)
   local result = pipeline.analyze_source(source, opts)
   pipeline.cover_and_expose(result, opts)
   return pipeline.finalize(result, opts)
end



--- Analyze files. `paths` is an array of file paths.
--
-- With `opts.whole_program`, the files are also analyzed as one program: calls
-- are followed across `require` boundaries inside the set, and a source in one
-- file reaching a sink in another is reported once, at the sink.
function api.analyze(paths, opts)
   opts = checked_options(opts)
   paths = checked_paths(paths)
   local findings = {}
   local files = {}
   local results = {}

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
      local result
      if detect.is_bytecode(file.source) then
         result = {path = file.path, findings = bytecode_triage.triage(file.source, opts),
            final = true}
      else
         result = pipeline.analyze_source(file.source, opts)
         result.path = file.path
      end
      -- Without the option a file's parsed program is finished with here and is
      -- released before the next one is read. Holding every file's check state
      -- until the end of the run is what lets the whole-program pass see them,
      -- and on a large tree it is the whole scan's ASTs in memory at once -- so
      -- it is paid only when the option asks for it.
      if not opts.whole_program then
         pipeline.cover_and_expose(result, opts)
         result.findings = pipeline.finalize(result, opts)
         result.chstate, result.state = nil, nil
      end
      results[#results + 1] = result
   end

   if opts.whole_program then
      pipeline.merge_whole_program(results, opts)
   end

   for _, result in ipairs(results) do
      if result.chstate then
         pipeline.cover_and_expose(result, opts)
         result.findings = pipeline.finalize(result, opts)
      end
      for _, finding in ipairs(result.findings) do
         finding.file = result.path
         findings[#findings + 1] = finding
      end
   end

   return pipeline.sort_findings(findings)
end

--- Render a report in the named format.
--
-- `report` is the raw findings list `check_source` and `analyze` return: it is
-- normalized against the report contract before rendering, so a caller does not
-- have to project findings onto it first. `name` is one of `"plain"`, `"json"`,
-- `"sarif"` or `"html"`; any other name returns nil plus the same "unknown
-- format" message the command line uses. Returns the rendered report, without a
-- trailing newline (the CLI's `emit` is what adds one).
function api.format(report, name, opts)
   return render.render(report_contract.normalize(report), name, opts)
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
