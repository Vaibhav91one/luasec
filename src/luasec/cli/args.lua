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
}

local BOOLEAN_FLAGS = {
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
   ["--ranges"] = "ranges",
   ["--no-config"] = "no_config",
}

-- Options that take a list. They are accepted both as `--opt value` and
-- `--opt=value`, and each occurrence is repeatable and comma separated.
-- `rules` is in here because api.configure iterates it with ipairs. It was
-- stored as a single string, so `ipairs("profile.json")` ran zero times and a
-- --rules file that did not exist, or did not parse, was accepted silently: the
-- operator's declarations never loaded and the report was quietly narrower.
local LIST_OPTIONS = {only = "only", ignore = "ignore", enable = "enable",
   rules = "rules"}

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

input:
  <path>                     Lua file, or directory to scan recursively

output:
  --format <name>            plain (default), json, sarif, html
  -o, --output <file>        write the report to a file instead of stdout
  --ranges                   include the end column of each finding
  --quiet                    print nothing when there are no findings
  --score                    print only the 0-100 health score (exit code unchanged)

selection:
  --std <names>              platform API sets, '+' separated, e.g. +openwrt+luci
  --only <patterns>          report only matching codes
  --ignore <patterns>        suppress matching codes
  --enable <patterns>        force matching codes on
  --rules <file>             load extra sink/source declarations. The file is a
                            Lua module returning a table, same shape as a
                            profile; a missing or unparseable one is an error,
                            never a silently narrower report. Repeatable.
  --severity-threshold <s>   lowest severity to report: low, medium, high, critical
                            (a file that could not be analyzed is always reported)
  --min-confidence <c>       lowest confidence to report: certain, high, medium, low
  --baseline <file.json>    report only what is new since that json report
  --fail-on <severity>       exit 1 at or above this severity
  --config <file>            read settings from this file (default: luasec.config.lua
                             in the current directory, if present)
  --no-config                ignore luasec.config.lua

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
  --jobs <n>                 parallel workers

validator exit codes: 0 benign, 1 rce, escape, partial or timeout, 2 the payload or
the sandbox itself failed.

other:
  -h, --help                 this message
  --version                  print version and exit

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
