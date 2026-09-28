-- Argument parsing. Hand written on purpose: the tool must run on a bare Lua
-- interpreter with no rocks installed.
local args = {}

local FLAGS_WITH_VALUE = {
   ["--format"] = "format",
   ["--std"] = "std",
   ["--profile"] = "profile",
   ["--severity-threshold"] = "severity_threshold",
   ["--min-confidence"] = "min_confidence",
   ["--baseline"] = "baseline",
   ["--fail-on"] = "fail_on",
   ["--rules"] = "rules",
   ["--output"] = "output",
   ["-o"] = "output",
   ["--jobs"] = "jobs",
   ["--max-iterations"] = "max_iterations",
   ["--min-length"] = "min_length",
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
   ["--codes"] = "codes",
   ["--ranges"] = "ranges",
   ["--verbose"] = "verbose",
}

-- Options that take a list. They are accepted both as `--opt value` and
-- `--opt=value`, and each occurrence is repeatable and comma separated.
local LIST_OPTIONS = {only = "only", ignore = "ignore", enable = "enable"}

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
      elseif token:sub(1, 1) == "-" and token ~= "-" then
         return nil, "unknown option " .. token
      else
         opts.paths[#opts.paths + 1] = token
         index = index + 1
      end
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
  --quiet                    only print the summary line

selection:
  --std <names>              platform API sets, '+' separated, e.g. +openwrt+luci
  --only <patterns>          report only matching codes
  --ignore <patterns>        suppress matching codes
  --enable <patterns>        force matching codes on
  --rules <file>             load additional sink/source declarations
  --profile <name>           strict, audit (default) or quick
  --severity-threshold <s>   lowest severity to report: low, medium, high, critical
  --min-confidence <c>       lowest confidence to report: certain, high, medium, low
  --baseline <file>          compare against a previous json report
  --fail-on <severity>       exit 1 at or above this severity

analysis:
  --whole-program            resolve calls across files
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

exit codes: 0 clean, 1 findings at or above the threshold, 2 error.
]]

function args.usage()
   return USAGE
end

return args
