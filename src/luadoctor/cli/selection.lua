-- Which findings a run reports: the config file's settings merged into the
-- options, a severity override, the --only/--ignore/--enable patterns and the
-- severity and confidence floors, then the config's allow list. In one place so
-- the scan, `lua-doctor why` and `lua-doctor fix` report the same findings for the
-- same flags.
local degraded = require "luadoctor.rules.degraded"
local categories = require "luadoctor.rules.categories"
local config_file = require "luadoctor.cli.config"

local selection = {}

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
   local wanted = nil
   if opts.category then
      wanted = {}
      for _, name in ipairs(opts.category) do wanted[name] = true end
   end

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

      if keep and wanted and not degraded.is_degraded(finding.code) then
         keep = wanted[categories.of(finding.code)] or false
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

selection.filter = apply_rules

--- Load the config (--config, else ./lua-doctor.config.lua unless --no-config)
-- and merge it into `opts`. Returns the settings table ({} when there is no
-- config), or nil plus a message.
function selection.settings(opts)
   -- The config file fills in what the command line left unset; a flag always
   -- wins. A config that cannot be read or checked is an error, not a default.
   local settings = {}
   if not opts.no_config then
      local path = opts.config
      if not path then
         local probe = io.open(config_file.DEFAULT_NAME, "rb")
         if probe then
            probe:close()
            path = config_file.DEFAULT_NAME
            io.stderr:write("lua-doctor: using lua-doctor.config.lua from the current directory ",
               "(--no-config to skip)\n")
         end
      end
      if path then
         local loaded, config_error = config_file.load(path)
         if not loaded then return nil, config_error end
         settings = loaded
      end
   end
   opts.std = opts.std or settings.std
   opts.fail_on = opts.fail_on or settings.fail_on
   for _, pattern in ipairs(settings.disable or {}) do
      opts.ignore = opts.ignore or {}
      opts.ignore[#opts.ignore + 1] = pattern
   end
   return settings
end

--- Apply the config's severity overrides to raw findings, in place.
function selection.override(report, settings)
   for _, finding in ipairs(report) do
      local override = settings.severity and settings.severity[finding.code]
      if override then finding.severity = override end
   end
end

return selection
