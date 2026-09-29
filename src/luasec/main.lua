-- CLI entry point.
local args_parser = require "luasec.cli.args"
local config_file = require "luasec.cli.config"
local walk = require "luasec.cli.walk"
local api = require "luasec.api"
local baseline = require "luasec.cli.baseline"
local codes = require "luasec.rules.codes"
local degraded = require "luasec.rules.degraded"
local json = require "luasec.report.json"
local plain = require "luasec.report.plain"
local report_contract = require "luasec.report.findings"
local render = require "luasec.report.render"
local validate_report = require "luasec.validate.report"
local version = require "luasec.version"

-- 0 clean, 1 findings at or above the threshold, 2 error, and 3 for the one thing
-- 1 cannot express: under --baseline, a finding that was not in the baseline. A
-- build script that already treats 1 as "fail" needs to be able to treat 3 as
-- "fail only if something is new", and a separate code is the only way to tell
-- the two apart without reading the report.
local EXIT_CLEAN, EXIT_FINDINGS, EXIT_ERROR, EXIT_NEW = 0, 1, 2, 3

-- Whether a file was fully analyzed is one question with one answer, asked in
-- three places: the exit code, the severity threshold, and the baseline. All
-- three read degraded.is_degraded, so they cannot disagree. See that module for
-- which codes qualify and, more importantly, which does not.

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
--
-- Same list as the exit code and the baseline use, from the same table: the
-- bytecode codes were once missing here, so `--severity-threshold critical` over
-- a .luac file printed nothing and exited 1 - the contradiction the --only path
-- was fixed for, surviving on the threshold path.
local INCOHERENT = {}
for _, degraded_code in ipairs(degraded.codes()) do INCOHERENT[degraded_code] = true end

local SEVERITY_RANK = {low = 1, medium = 2, high = 3, critical = 4}
local CONFIDENCE_RANK = {low = 1, medium = 2, high = 3, certain = 4}

local function fail(message)
   io.stderr:write("luasec: " .. message .. "\n")
   return EXIT_ERROR
end

-- Pattern rules shared with luacheck: a pattern is a code, optionally with a
-- name after a colon, and may use character classes like "7", "[1234]".
--
-- The code is the SUBJECT and the operator's pattern is the PATTERN. The other
-- way round, the argument order reads plausibly enough to survive review: the
-- result is that every multi-character pattern matches nothing, because
-- string.match("70", "709") is nil. So `--only 70`, `--only 7` and the
-- documented `--only 70[0-9]` all reported an empty tree and exited 0.
--
-- A malformed pattern is pcall'd for the same reason as everywhere else: the
-- pattern is text from the command line or from a file, and neither is
-- something we validated.
local function matches(subject, pattern)
   local ok, result = pcall(string.match, subject or "", pattern)
   return ok and result ~= nil
end

local function pattern_matches(pattern, finding)
   local code_pattern, name_pattern = pattern:match("^([^:]*):?(.*)$")
   local codes_ok = code_pattern == "" or matches(finding.code, code_pattern)
   local name_ok = name_pattern == ""
      or (finding.name ~= nil and matches(finding.name, name_pattern))
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

      -- --only narrows what the operator wants to READ. It does not remove the
      -- evidence that a file was never analyzed: `--only 708` on a tree with
      -- an unreadable directory would otherwise print a clean report and exit
      -- non-zero, which reads as a contradiction. --ignore is the flag that
      -- takes a code out of the report, so --ignore 901 still does that.
      if keep and opts.only and not degraded.is_degraded(finding.code) then
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
-- when the caller has one, which is how a baseline run can render its own; the
-- renderer renders it as given, so the per-finding status a baseline carries
-- is not dropped by re-normalizing.

-- Write the report where the caller asked for it. Kept in one place because the
-- baseline path and the ordinary path must obey the same -o and --quiet
-- contract, or a report that only appears on one of them is worse than neither.
local function emit(list, format, opts)
   -- --score answers one question, so it prints one number and nothing else.
   local output
   if opts.score then
      output = tostring(api.score(list).score)
   else
      output = render.render(list, format, opts)
   end

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

-- Subcommands, recognised only as the first word, exactly, so a path is never
-- mistaken for one: a directory called rules is scanned as ./rules. Each module
-- exposes run(argv, root) with the words after the subcommand and the
-- installation directory, and returns the exit code.
local SUBCOMMANDS = {
   fix = "luasec.cli.fix_cmd",
   install = "luasec.cli.install_cmd",
   rules = "luasec.cli.rules_cmd",
   why = "luasec.cli.why_cmd",
}

local function run(argv)
   local subcommand = SUBCOMMANDS[argv[1]]
   if subcommand then
      local root = (arg and arg[0] or ""):match("^(.*)/src/luasec/main%.lua$") or "."
      -- luasec: ignore 705  the module name comes from the SUBCOMMANDS table above, not from input
      return require(subcommand).run({table.unpack(argv, 2)}, root)
   end
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

   -- A format we do not have used to fall back to plain text, so
   -- `--format json -o report.json` wrote prose into a file a CI then handed to
   -- jq, and the failure surfaced downstream as a parse error in a tool that
   -- was never wrong. A typo in a flag is a config error, like the numbers.
   local FORMAT_NAMES = {plain = true, json = true, sarif = true, html = true}
   if opts.format and not FORMAT_NAMES[opts.format] then
      return fail(("unknown format '%s': expected plain, json, sarif or html")
         :format(opts.format))
   end

   -- The config file fills in what the command line left unset; a flag always
   -- wins. A config that cannot be read or checked is an error, not a default.
   local settings = {}
   if not opts.no_config then
      local path = opts.config
      if not path then
         local probe = io.open(config_file.DEFAULT_NAME, "rb")
         if probe then probe:close() path = config_file.DEFAULT_NAME end
      end
      if path then
         local loaded, config_error = config_file.load(path)
         if not loaded then return fail(config_error) end
         settings = loaded
      end
   end
   opts.std = opts.std or settings.std
   opts.fail_on = opts.fail_on or settings.fail_on
   for _, pattern in ipairs(settings.disable or {}) do
      opts.ignore = opts.ignore or {}
      opts.ignore[#opts.ignore + 1] = pattern
   end

   -- `--max-nodes $UNSET_VAR` reached the analysis as the string "abc" and
   -- `max_nodes + 1` raised out of the CLI as a traceback with exit 1, which
   -- this tool defines as "findings": a CI with a typo in a variable gets a
   -- security result instead of a config error.
   for _, option in ipairs({"jobs", "max_nodes", "validate_timeout"}) do
      local raw = opts[option]
      if raw ~= nil then
         local value = tonumber(raw)
         -- An integer, because the message says so and a fractional node cap is
         -- a half-node cap, which is not a thing.
         if not value or value < 1 or value % 1 ~= 0 then
            return fail(("--%s needs a positive integer"):format(
               option:gsub("_", "-")))
         end
      end
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

   -- Ground we did not cover, counted before any filtering is applied. A file
   -- that could not be read, a directory that could not be listed and a file
   -- analyzed only approximately are absences, not clean results.
   --
   -- The 9xx codes are this rule's own vocabulary, so the check reads the code
   -- rather than a phrase in the message. Matching on the message text meant
   -- 901 parse failures and 904 skipped analyses were never counted, and
   -- --only 708 deleted the 901 before this code ever saw it.
   for _, finding in ipairs(report) do
      local override = settings.severity and settings.severity[finding.code]
      if override then finding.severity = override end
   end

   local unanalyzed = 0
   for _, finding in ipairs(report) do
      if degraded.is_degraded(finding.code) then
         unanalyzed = unanalyzed + 1
      end
   end

   report = apply_rules(report, opts)

   report = config_file.apply_allow(report, settings.allow)

   -- Counted above, acted on after the report is written: a run that skipped
   -- part of its input still has to show what it found, and the count is taken
   -- before --only or --ignore can delete the evidence.
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

   -- --only exists to select, so an empty selection is either a typo or the
   -- operator looking at the wrong file. `--only 70(` is the first: Lua reads it
   -- as a pattern, it matches nothing, and a file with a high-severity RCE came
   -- back clean. It cannot be made an error, because `--only 709` on a file with
   -- no 709 is legitimate, so it is said out loud instead. Silence from luasec
   -- means "looked at it and found nothing", and a warning says which of those
   -- two this was.
   if opts.only and #list == 0 then
      io.stderr:write("luasec: --only selected nothing: "
         .. table.concat(opts.only, ", ")
         .. " (no finding matched; is the pattern what you meant?)\n")
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
