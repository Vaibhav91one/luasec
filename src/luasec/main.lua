-- CLI entry point.
local args_parser = require "luasec.cli.args"
local walk = require "luasec.cli.walk"
local api = require "luasec.api"
local baseline = require "luasec.cli.baseline"
local codes = require "luasec.rules.codes"
local json = require "luasec.report.json"
local plain = require "luasec.report.plain"
local sarif = require "luasec.report.sarif"
local report_contract = require "luasec.report.findings"
local validate_report = require "luasec.validate.report"
local version = require "luasec.version"

-- 0 clean, 1 findings at or above the threshold, 2 error, and 3 for the one thing
-- 1 cannot express: under --baseline, a finding that was not in the baseline. A
-- build script that already treats 1 as "fail" needs to be able to treat 3 as
-- "fail only if something is new", and a separate code is the only way to tell
-- the two apart without reading the report.
local EXIT_CLEAN, EXIT_FINDINGS, EXIT_ERROR, EXIT_NEW = 0, 1, 2, 3

-- A verdict is an outcome, not a threshold: anything short of "benign" means the
-- payload did something worth failing a build over, and a failed payload or a
-- broken sandbox is a different thing again. `escape` is a process-control
-- attempt that executed nothing, and it fails the build for the same reason any
-- other reach does: the snippet tried to leave the sandbox.
local VERDICT_EXIT = {benign = EXIT_CLEAN, rce = EXIT_FINDINGS,
                      escape = EXIT_FINDINGS, partial = EXIT_FINDINGS,
                      timeout = EXIT_FINDINGS, error = EXIT_ERROR}

-- Which fields of a validation verdict are text the payload chose. It is rendered
-- into the JSON rather than left to documentation, because the JSON is what a
-- machine acts on.
local UNTRUSTED_NOTE = "payload_* fields, and the arg of a sink, are text the validated snippet "
   .. "chose; they are reported as data, not as luasec findings"

-- Findings that describe what WE could not do, rather than what the code does.
-- A threshold must never turn "we did not analyze this" into "clean", because an
-- operator running --severity-threshold high over a firmware tree would get a
-- green build for every file that failed to parse.
local INCOHERENT = {
   ["901"] = true,  -- could not parse
   ["904"] = true,  -- analyzed approximately
   ["021"] = true,  -- a suppression the operator asked for could not be read
   ["902"] = true,  -- dialect the parser cannot read
}

local SEVERITY_RANK = {low = 1, medium = 2, high = 3, critical = 4}
local CONFIDENCE_RANK = {low = 1, medium = 2, high = 3, certain = 4}

local function fail(message)
   io.stderr:write("luasec: " .. message .. "\n")
   return EXIT_ERROR
end

-- Pattern rules shared with luacheck: a pattern is a code, optionally with a
-- name after a colon, and may use character classes like "7", "[1234]".
local function pattern_matches(pattern, finding)
   local code_pattern, name_pattern = pattern:match("^([^:]*):?(.*)$")
   local codes_ok = code_pattern == "" or code_pattern:match(finding.code) ~= nil
   local name_ok = name_pattern == "" or (finding.name and finding.name:match(name_pattern) ~= nil)
   return codes_ok and name_ok
end

local function apply_rules(findings, opts)
   local result = {}

   for _, finding in ipairs(findings) do
      local keep = true

      for _, pattern in ipairs(opts.ignore or {}) do
         if pattern_matches(pattern, finding) then keep = false break end
      end

      for _, pattern in ipairs(opts.enable or {}) do
         if pattern_matches(pattern, finding) then keep = true end
      end

      if keep and opts.only then
         keep = false
         for _, pattern in ipairs(opts.only) do
            if pattern_matches(pattern, finding) then keep = true break end
         end
      end

      if keep and opts.severity_threshold and not INCOHERENT[finding.code] then
         if (SEVERITY_RANK[finding.severity] or 0) < (SEVERITY_RANK[opts.severity_threshold] or 0) then
            keep = false
         end
      end

      if keep and opts.min_confidence then
         if (CONFIDENCE_RANK[finding.confidence] or 0) < (CONFIDENCE_RANK[opts.min_confidence] or 0) then
            keep = false
         end
      end

      if keep then result[#result + 1] = finding end
   end

   return result
end

local function worst_severity(findings)
   local worst = nil
   for _, finding in ipairs(findings) do
      if not worst or plain.severity_rank(finding.severity) > plain.severity_rank(worst) then
         worst = finding.severity
      end
   end
   return worst
end

-- Every format is rendered from the contract, not from the engine's raw
-- findings, so `plain`, `json`, `sarif` and `html` cannot disagree about what a
-- finding is or in what order it appears. `list` is an already normalized list
-- when the caller has one, which is how a baseline run can render its own.
local function render(list, format, opts)
   list = list or report_contract.normalize(list)
   if format == "json" then
      return json.encode(report_contract.document(list))
   elseif format == "sarif" then
      return sarif.render(list, opts)
   elseif format == "html" then
      return require("luasec.report.html").render(list, opts)
   end
   return plain.render(list, opts)
end

-- Write the report where the caller asked for it. Kept in one place because the
-- baseline path and the ordinary path must obey the same -o and --quiet
-- contract, or a report that only appears on one of them is worse than neither.
local function emit(list, format, opts)
   local output = render(list, format, opts)

   if opts.output then
      local handle, open_error = io.open(opts.output, "wb")
      if not handle then return fail("cannot write " .. opts.output .. ": " .. tostring(open_error)) end
      handle:write(output, "\n")
      handle:close()
   elseif not opts.quiet or #list > 0 then
      io.stdout:write(output, "\n")
   end

   return nil
end

-- Read the payload to validate. One file, or standard input, because a verdict
-- is about a single snippet: a directory of candidates is several runs.
local function read_payload(opts)
   if opts.stdin then
      return io.read("*a"), "<stdin>"
   end

   if #opts.paths ~= 1 then
      return nil, nil, "--validate needs exactly one file, or --stdin"
   end

   local handle, open_error = io.open(opts.paths[1], "rb")
   if not handle then
      return nil, nil, "cannot read " .. opts.paths[1] .. ": " .. tostring(open_error)
   end
   local source = handle:read("*a")
   handle:close()
   return source, opts.paths[1]
end

-- The dynamic half of the tool: decide whether a snippet actually achieves
-- execution, by running it in a child process. It never runs here.
local function validate(opts)
   local source, name, read_error = read_payload(opts)
   if read_error then return fail(read_error) end

   local verdict = api.validate_payload(source, {
      lua = os.getenv("LUASEC_LUA"),
      timeout_ms = tonumber(opts.validate_timeout),
      name = name,
   })

   local output
   if opts.format == "json" then
      -- The note travels with the data: a machine reader has to be able to see,
      -- without reading this source, which of these fields are the payload's
      -- words rather than luasec's.
      local validation = {note = UNTRUSTED_NOTE}
      for key, value in pairs(verdict) do validation[key] = value end
      output = json.encode({version = version.luasec, validation = validation})
   elseif opts.format == "sarif" or opts.format == "html" then
      return fail("--validate supports --format plain and --format json")
   else
      output = validate_report.render(verdict, name)
   end

   if opts.output then
      local handle, open_error = io.open(opts.output, "wb")
      if not handle then return fail("cannot write " .. opts.output .. ": " .. tostring(open_error)) end
      handle:write(output, "\n")
      handle:close()
   else
      io.stdout:write(output, "\n")
   end

   return VERDICT_EXIT[verdict.verdict] or EXIT_ERROR
end

local function run(argv)
   local opts, parse_error = args_parser.parse(argv)
   if not opts then return fail(parse_error) end

   if opts.help then
      io.stdout:write(args_parser.usage())
      return EXIT_CLEAN
   end

   if opts.version then
      io.stdout:write(string.format("luasec %s (luacheck %s, rules %s)\n",
         version.luasec, version.luacheck, version.rules_pack))
      return EXIT_CLEAN
   end

   if opts.validate then
      return validate(opts)
   end

   if #opts.paths == 0 and not opts.help and not opts.version then
      io.stdout:write(args_parser.usage())
      return EXIT_ERROR
   end

   if opts.jobs then
      local jobs = tonumber(opts.jobs)
      if not jobs or jobs < 1 then return fail("--jobs needs a positive integer") end
   end

   local options_ok, options_error = api.validate_options(opts)
   if not options_ok then return fail(options_error) end

   local files, walk_errors = walk.collect(opts.paths)
   if not files then return fail(walk_errors) end

   -- A path we could not read is reported as its own finding, so the run fails
   -- on it instead of quietly covering less ground than asked.
   local report = {}
   for _, problem in ipairs(walk_errors or {}) do
      report[#report + 1] = {
         code = "901", line = 1, column = 1, end_column = 1,
         severity = "low", confidence = "certain", cwe = "CWE-0",
         name = problem.path or "unreadable path",
         file = problem.path,
         message = "not analyzed: " .. problem.message,
      }
   end
   for _, finding in ipairs(api.analyze(files, opts)) do
      report[#report + 1] = finding
   end
   report = apply_rules(report, opts)

   -- Ground we did not cover. A file that could not be read and a directory
   -- that could not be listed are both absences, not clean results, and
   -- --fail-on exists to quieten low-severity findings rather than to excuse
   -- them. This is checked before the baseline too: a baseline knows which
   -- findings are old, not which parts of the tree were skipped.
   local unanalyzed = 0
   for _, finding in ipairs(report) do
      local message = type(finding.message) == "string" and finding.message or ""
      if message:find("not analyzed", 1, true)
         or message:find("cannot read file", 1, true) then
         unanalyzed = unanalyzed + 1
      end
   end
   -- Counted here, acted on after the report is written: a run that skipped
   -- part of its input still has to show what it found.
   local ground_missing = unanalyzed > 0

   local threshold_rank = SEVERITY_RANK[opts.fail_on or "low"] or 0

   if opts.baseline then
      local known, baseline_error = baseline.read(opts.baseline)
      if not known then return fail(baseline_error) end

      local list, exceeded = baseline.compare(report_contract.normalize(report), known,
         threshold_rank)

      -- Under a baseline only a new finding is a reason to fail. A known one is
      -- what the baseline is for, and a fixed one is an improvement. A finding
      -- below the threshold is reported and does not fail, exactly as it does
      -- without a baseline.
      local written = emit(list, opts.format or "plain", opts)
      if written then return written end
      if ground_missing then return EXIT_FINDINGS end
      return exceeded and EXIT_NEW or EXIT_CLEAN
   end

   local list = report_contract.normalize(report)
   local written = emit(list, opts.format or "plain", opts)
   if written then return written end

   if ground_missing then
      return EXIT_FINDINGS
   end

   if #list == 0 then
      return EXIT_CLEAN
   end

   if (SEVERITY_RANK[worst_severity(list)] or 0) >= threshold_rank then
      return EXIT_FINDINGS
   end

   return EXIT_CLEAN
end

os.exit(run(arg or {}))
