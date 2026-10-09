-- Argument parsing. Hand written on purpose: the tool must run on a bare Lua
-- interpreter with no rocks installed.
local args = {}

local FLAGS_WITH_VALUE = {
   ["--format"] = "format",
   ["--config"] = "config",
   ["--std"] = "std",
   ["--severity-threshold"] = "severity_threshold",
   ["--min-confidence"] = "min_confidence",
   ["--baseline"] = "baseline",
   ["--fail-on"] = "fail_on",
   ["--rules"] = "rules",
   ["--output"] = "output",
   ["-o"] = "output",
   ["--jobs"] = "jobs",
   ["--max-nodes"] = "max_nodes",
   ["--validate-timeout"] = "validate_timeout",
   ["--view"] = "view",
   ["--scope"] = "scope",
   ["--base"] = "base",
   ["--sarif"] = "sarif",
}

local BOOLEAN_FLAGS = {
   ["--json"] = "json",
   ["--version"] = "version",
   ["--help"] = "help",
   ["-h"] = "help",
   ["--whole-program"] = "whole_program",
   ["--validate"] = "validate",
   ["--stdin"] = "stdin",
   ["--no-raw-scan"] = "no_raw_scan",
   ["--no-dynamic-sinks"] = "no_dynamic_sinks",
   ["--quiet"] = "quiet",
   ["--score"] = "score",
   ["--summary"] = "summary",
   ["--ranges"] = "ranges",
   ["--no-config"] = "no_config",
   ["--progress"] = "progress",
   ["--no-progress"] = "no_progress",
   ["--color"] = "color",
   ["--no-color"] = "no_color",
   ["--verbose"] = "verbose",
   ["--staged"] = "staged",
   ["--include-untracked"] = "include_untracked",
   ["--interactive"] = "interactive",
   ["--no-interactive"] = "no_interactive",
}

-- Options that take a list. They are accepted both as `--opt value` and
-- `--opt=value`, and each occurrence is repeatable and comma separated.
-- `rules` is in here because api.configure iterates it with ipairs. It was
-- stored as a single string, so `ipairs("profile.json")` ran zero times and a
-- --rules file that did not exist, or did not parse, was accepted silently: the
-- operator's declarations never loaded and the report was quietly narrower.
local LIST_OPTIONS = {only = "only", ignore = "ignore", enable = "enable",
   category = "category", rules = "rules"}

local function add_list(target, name, value)
   target[name] = target[name] or {}
   for part in value:gmatch("[^,]+") do
      target[name][#target[name] + 1] = part
   end
end

for name in pairs(LIST_OPTIONS) do
   FLAGS_WITH_VALUE["--" .. name] = name
end

--- Parse argv (array, without the program name).
-- Returns options table, or nil plus an error message.
function args.parse(argv)
   local opts = {paths = {}}
   local index = 1

   while index <= #argv do
      local token = argv[index]

      if BOOLEAN_FLAGS[token] then
         opts[BOOLEAN_FLAGS[token]] = true
         index = index + 1
      elseif token:match("^%-%-[%w%-]+=") then
         local name, value = token:match("^(%-%-[%w%-]+)=(.*)$")
         local key = FLAGS_WITH_VALUE[name]
         if not key then
            return nil, "unknown option " .. name
         end
         if LIST_OPTIONS[key] then
            add_list(opts, key, value)
         else
            opts[key] = value
         end
         index = index + 1
      elseif FLAGS_WITH_VALUE[token] then
         local value = argv[index + 1]
         if not value then
            return nil, "option " .. token .. " needs a value"
         end
         local key = FLAGS_WITH_VALUE[token]
         if LIST_OPTIONS[key] then
            add_list(opts, key, value)
         else
            opts[key] = value
         end
         index = index + 2
      elseif token == "--" then
         for rest = index + 1, #argv do
            opts.paths[#opts.paths + 1] = argv[rest]
         end
         break
      elseif token:sub(1, 1) == "-" and token ~= "-" then
         return nil, "unknown option " .. token
      else
         opts.paths[#opts.paths + 1] = token
         index = index + 1
      end
   end

   -- --json is the doctor/1 spelling of --format json.
   if opts.json then
      if opts.format and opts.format ~= "json" then
         return nil, "--json conflicts with --format " .. opts.format
      end
      opts.format = "json"
   end

   -- --no-dynamic-sinks is a CLI-facing name; the engine reads report_dynamic_sinks.
   -- Translate here so the rest of the pipeline sees the flag it expects, and a
   -- library caller using report_dynamic_sinks directly is unaffected.
   if opts.no_dynamic_sinks then
      opts.report_dynamic_sinks = false
   end

   return opts
end

local USAGE = [[
luasec - RCE checker and security analyzer for Lua in embedded firmware

usage: luasec [options] <file|directory>...
       luasec mcp
       luasec rules [list | explain <code>]
       luasec why <file>:<line> [options]
       luasec fix [--agent claude|codex|cursor] [--safe] [--print] <path>...
      luasec install [--dir <project>] [--force] [--hook] [claude] [cursor] [agents]
      luasec install [--dir <project>] [--force] [claude] [cursor] [agents]
       luasec ci install [--dir <project>] [--force]

input:
  <path>                     Lua file, or directory to scan recursively

output:
  --format <name>            plain (default), json, sarif, html
  --json                     the machine-readable doctor/1 envelope (same as --format json)
  --sarif <file>             also write SARIF 2.1.0 to this file
  -o, --output <file>        write the report to a file instead of stdout
  --ranges                   include the end column of each finding
  --quiet                    print nothing when there are no findings
  --score                    print only the 0-100 health score (exit code unchanged)
  --summary                  print counts and the files with the most findings, not every finding
  --view <list|doctor>       doctor: findings grouped by code with the score (default on a terminal)
  --verbose                  with the doctor view: every code and every location
  --interactive              offer a menu after the report (default: on a terminal)
  --no-interactive           never offer the menu
  --progress                 show progress on stderr (default: only on a terminal)
  --no-progress              never show progress
  --color                    force colour (default: only on a terminal, never with NO_COLOR)
  --no-color                 never use colour

selection:
  --std <names>              platform API sets, '+' separated, e.g. +openwrt+luci
  --only <patterns>          report only matching codes
  --ignore <patterns>        suppress matching codes
  --enable <patterns>        force matching codes on
  --category <names>         only these families: exec, firmware, payload, artifact, meta
  --rules <file>             load extra sink/source declarations. The file is a
                            Lua module returning a table, same shape as a
                            profile; a missing or unparseable one is an error,
                            never a silently narrower report. Repeatable.
  --severity-threshold <s>   lowest severity to report: low, medium, high, critical
                            (a file that could not be analyzed is always reported)
  --min-confidence <c>       lowest confidence to report: certain, high, medium, low
  --baseline <file.json>    report only what is new since that --json envelope
  --fail-on <severity>       exit 1 at or above this severity (info, low, medium, high,
                             critical; default low)
  --config <file>            read settings from this file (default: luasec.config.lua
                             in the current directory, if present)
  --no-config                ignore luasec.config.lua
  --scope <full|changed>     changed: only files changed since --base (default: main); full is the default
  --base <ref>               with --scope changed: the ref to compare with
  --include-untracked        with --scope changed: also scan new, untracked files
  --staged                   only files staged in git (for a pre-commit hook)

analysis:
  --whole-program            resolve calls across files. Follows require edges
                             and passes taint into a required module's
                             parameters, and a local function's and a module
                             field's return in one file is followed, and
                             under --whole-program the return of a function in
                             a module bound with local m = require "mod" is
                             followed too; not followed: a method call (M:m),
                             a function passed as a value, require(...) called
                             inline in an expression, and anything past the depth
                             cap.
  --no-dynamic-sinks         only report sinks fed by known untrusted data
  --no-raw-scan              skip the lexical scan used when parsing fails
  --validate                 run the payload validator instead of static analysis
  --max-nodes <n>            node budget before analysis degrades (default 20000)
  --stdin                    with --validate, read the payload from standard input
  --validate-timeout <ms>    wall clock for one validated payload (default 2000)
  --jobs <n>                 analyze files in n worker processes (--whole-program
                             runs in one process)

validator exit codes: 0 benign, 1 rce, escape, partial or timeout, 2 the payload or
the sandbox itself failed.

other:
  -h, --help                 this message
  --version                  print version and exit
  mcp                        serve the scan tool over MCP (stdio)
  rules list | explain <code>  the rule catalogue, and one code's doc page
  rules set|enable|disable <code>  tune what this project reports (edits luasec.config.lua)
  why <file>:<line>          explain the findings on one line and how to fix them
  fix                        hand the findings to an AI agent (approvals skipped unless --safe)
  install                    write agent guidance: Claude skill, Cursor rule, AGENTS.md
  ci install                 write a GitHub workflow that runs the luasec action

with --baseline: 0 nothing new, 3 at least one new finding at or above --fail-on.
A finding already in the baseline is not reported, and one that was in the
baseline and is no longer found is reported as fixed.

exit codes: 0 clean, 1 findings at or above the threshold, 2 error,
3 new findings at or above the threshold (--baseline only).
]]

function args.usage()
   return USAGE
end

return args
