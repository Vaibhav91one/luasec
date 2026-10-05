-- Lint luasec's own source with the vendored luacheck.
--
--   lua test/self-lint.lua [--baseline FILE] [--bless] [DIR]
--
-- Exits 0 when the warnings under DIR are exactly the ones listed in the
-- baseline, 1 when they have drifted, and 2 when the lint could not run at all
-- - no vendored luacheck, no baseline, an empty DIR. Exit 2 is deliberately
-- not folded into exit 1: a lint that cannot read its input must say which of
-- the three it was rather than report a clean tree.
--
-- Why a baseline at all. `make selfscan` runs luasec over src/ and luasec has
-- no rule for a global assignment, so a function that lost its `local`
-- compiled, worked, and shipped as a global; nothing in the build noticed
-- (#277). luacheck's 111 does notice it. But src/ does not currently lint
-- clean - it carries 111 and 113 of its own - so the honest way to add this
-- gate is as a ratchet over what is already there rather than as a wall that
-- starts red. A file that has never been seen to fail is a gate nobody knows
-- works, so the failure path is exercised in the PR, not asserted here.
--
-- The baseline is an exact multiset, not a threshold: it names a path, a code
-- and a name, and a warning is permitted only because a line says so. Drift in
-- either direction fails - a new warning, and a baselined warning that no
-- longer happens - so the list can never come to describe a set of warnings
-- that stopped existing.
--
-- Paths are relative to DIR, so a scratch copy of src/ at any location is
-- checked against the same baseline. That is how the gate was proved to fail:
-- copy src/, add a global, and the only difference is the one warning.

local luacheck = require "luacheck"
local format = require "luacheck.format"

-- luacheck's own defaults, written out rather than inherited: a change in an
-- upstream default must move this gate by way of a diff somebody reviewed, not
-- by way of a new baseline nobody read.
local OPTIONS = {std = "max", max_line_length = 120}

local DEFAULT_DIR = "src"
local DEFAULT_BASELINE = "test/self-lint-baseline.txt"

-- luacheck's file discovery needs LuaFileSystem, a C module this project does
-- not build and does not want: AGENTS.md puts the whole dependency story at one
-- locally built Lua. `find` is already what the spec runner and the release
-- tarball use, so the walk is the one already in this repository.
local function lua_files(dir, acc)
   local pipe = io.popen(("find %q -type f -name '*.lua' 2>/dev/null | LC_ALL=C sort")
      :format(dir))
   if not pipe then return acc end
   for path in pipe:lines() do
      if path ~= "" then acc[#acc + 1] = path end
   end
   pipe:close()
   return acc
end

-- One warning, identified the way the baseline identifies it: where it is,
-- which luacheck code raised it, and what it is about. The line number is
-- deliberately not part of the key - an unrelated edit above a baselined
-- warning would otherwise turn the gate red for a change that fixed nothing
-- and broke nothing.
local function key_of(path, warning)
   return ("%s\t%s\t%s"):format(path, warning.code, tostring(warning.name))
end

local function run_luacheck(dir)
   local files = lua_files(dir, {})
   local names = {}
   for i, path in ipairs(files) do
      names[i] = path:gsub("^" .. dir:gsub("(%W)", "%%%1") .. "/", "")
   end

   if #files == 0 then
      return nil, ("%s contains no .lua files: the lint would pass without reading a line")
         :format(dir)
   end

   local ok, report = pcall(luacheck.check_files, files, OPTIONS)
   if not ok then
      return nil, "luacheck could not run: " .. tostring(report)
   end

   local keys, fatals = {}, {}
   for i, file_report in ipairs(report) do
      if file_report.fatal then
         fatals[#fatals + 1] = ("%s: %s"):format(names[i], tostring(file_report.msg))
      else
         for _, warning in ipairs(file_report) do
            keys[#keys + 1] = key_of(names[i], warning)
         end
      end
   end
   if #fatals > 0 then
      return nil, "luacheck could not read these files:\n    " .. table.concat(fatals, "\n    ")
   end

   return {keys = keys, names = names, report = report}
end

local function read_baseline(path)
   local handle = io.open(path, "r")
   if not handle then
      return nil, nil, ("%s does not exist. A lint with no baseline accepts everything it is "
         .. "shown, so it cannot fail."):format(path)
   end
   local keys, header = {}, {}
   local in_header = true
   for line in handle:lines() do
      line = line:gsub("^%s+", ""):gsub("%s+$", "")
      if in_header and line:sub(1, 1) == "#" then
         header[#header + 1] = line
      elseif line ~= "" and line:sub(1, 1) ~= "#" then
         in_header = false
         keys[#keys + 1] = line
      end
   end
   handle:close()
   return keys, header
end

-- The header is carried across a re-bless. A baseline whose explanation is in
-- the file gets a blank first line on the next `--bless`, and a bare list of
-- 116 warnings is a much easier thing to approve without reading than a list
-- of 116 warnings that says which seven of them are the leak #277 is about.
local function write_baseline(path, header, keys)
   local handle = assert(io.open(path, "w"))
   handle:write(table.concat(header, "\n"), "\n")
   handle:write(table.concat(keys, "\n"), "\n")
   handle:close()
end

local function counts(list)
   local seen = {}
   for _, key in ipairs(list) do seen[key] = (seen[key] or 0) + 1 end
   return seen
end

-- The keys that are in `left` and not in `right`, keeping a repeated key
-- repeated: a baseline listing the same warning twice covers two warnings,
-- not one.
local function difference(left, right)
   local have = counts(right)
   local out = {}
   for _, key in ipairs(left) do
      if have[key] and have[key] > 0 then
         have[key] = have[key] - 1
      else
         out[#out + 1] = key
      end
   end
   return out
end

-- One line per warning, in luacheck's own `file:line:col: (Wcode) message`
-- shape, so a warning this gate reports reads exactly as it would if anyone ran
-- luacheck over the same file. format.get_message is used rather than the
-- built-in `default` formatter because that one wants the whole CLI options
-- table and the report totals, which are the CLI's business and not this
-- gate's.
local function render(names, report, keep)
   local lines = {}
   for i, file_report in ipairs(report) do
      for _, warning in ipairs(file_report) do
         if not keep or keep[key_of(names[i], warning)] then
            lines[#lines + 1] = ("%s:%d:%d: (%s%s) %s"):format(
               names[i], warning.line, warning.column or 1,
               warning.code:sub(1, 1) == "0" and "E" or "W", warning.code,
               format.get_message(warning))
         end
      end
   end
   table.sort(lines)
   return lines
end

local function parse_args(argv)
   local opts = {dir = DEFAULT_DIR, baseline = DEFAULT_BASELINE, bless = false}
   local positional = {}
   -- arg carries negative indices too (arg[-1] is the interpreter), and `#` is
   -- a border search, not a length: on `lua x.lua a b` it answers 1. A while
   -- over the real end is the only count that is right here. A numeric for
   -- would not do either - it ignores an assignment to its own control
   -- variable, so --baseline would eat its value and then see it again.
   local i = 1
   while argv[i] do
      local arg = argv[i]
      if arg == "--bless" then
         opts.bless = true
      elseif arg == "--baseline" then
         i = i + 1
         if not argv[i] then return nil, "--baseline needs a file" end
         opts.baseline = argv[i]
      elseif arg == "-h" or arg == "--help" then
         opts.help = true
      elseif arg:sub(1, 1) == "-" then
         return nil, ("unknown option %q; usage: self-lint.lua [--baseline FILE] [--bless] [DIR]")
            :format(arg)
      else
         positional[#positional + 1] = arg
      end
      i = i + 1
   end
   if #positional > 1 then
      return nil, "usage: self-lint.lua [--baseline FILE] [--bless] [DIR]"
   end
   if #positional == 1 then opts.dir = positional[1] end
   return opts
end

local function main(argv)
   local opts, arg_error = parse_args(argv)
   if not opts then
      io.stderr:write("self-lint: FAIL - ", arg_error, "\n")
      return 2
   end
   if opts.help then
      io.write("usage: self-lint.lua [--baseline FILE] [--bless] [DIR]\n")
      return 0
   end

   local run, run_error = run_luacheck(opts.dir)
   if not run then
      io.stderr:write("self-lint: FAIL - ", run_error, "\n")
      return 2
   end
   table.sort(run.keys)

   local known, header, known_error = read_baseline(opts.baseline)
   if not known then
      -- --bless is the one command whose job is to write the file, so a missing
      -- one is what it is for. Every other path treats it as the failure it is:
      -- a lint with nothing to compare against cannot fail, and a gate that
      -- cannot fail is worse than no gate because it reads like one.
      if not opts.bless then
         io.stderr:write("self-lint: FAIL - ", known_error, "\n")
         return 2
      end
      known, header = {}, {}
   end
   table.sort(known)

   local added = difference(run.keys, known)
   local added_set = {}
   for _, key in ipairs(added) do added_set[key] = true end
   local gone = difference(known, run.keys)

   if #added == 0 and #gone == 0 then
      io.write(("self-lint: ok (%d files, %d warnings, all baselined in %s)\n")
         :format(#run.names, #run.keys, opts.baseline))
      return 0
   end

   if opts.bless then
      write_baseline(opts.baseline, header, run.keys)
      io.write(("self-lint: wrote %s (%d warnings, %d added, %d removed)\n")
         :format(opts.baseline, #run.keys, #added, #gone))
      for _, line in ipairs(render(run.names, run.report, added_set)) do
         io.write("  ", line, "\n")
      end
      return 0
   end

   io.stderr:write(("self-lint: FAIL - %d warning%s under %s %s not in %s\n"):format(
      #added, #added == 1 and "" or "s", opts.dir, #added == 1 and "is" or "are", opts.baseline))
   for _, line in ipairs(render(run.names, run.report, added_set)) do
      io.stderr:write("  ", line, "\n")
   end
   if #gone > 0 then
      io.stderr:write(("\n  and %d baselined warning%s no longer happens, which is an "
         .. "improvement to record rather than to carry:\n"):format(#gone, #gone == 1 and "" or "s"))
      for _, key in ipairs(gone) do
         io.stderr:write("    ", (key:gsub("\t", "  ")), "\n")
      end
      io.stderr:write("\n  Re-run `make self-lint-bless` once the tree is as you want it.\n")
   end
   io.stderr:write("\n  A new global is luacheck 111/113: add `local` where it is defined.\n")
   return 1
end

os.exit(main(arg or {}))