-- Minimal zero-dependency test harness.
--
-- Public surface used by every spec:
--   describe(name, fn)   group
--   it(name, fn)         one behavior
--   assert_equal(a, b [, msg]) / assert_true / assert_nil / assert_match / assert_error
--   run(dirs)            execute all spec files under the given directories
--
-- A spec fails when `it` raises. `run` returns (passed, failures) and the process
-- exit code is non-zero if anything failed.
local harness = {}

local groups = {}
local current
local results

local function describe(name, fn)
   current = {name = name, specs = {}}
   table.insert(groups, current)
   fn()
   current = nil
end

local function it(name, fn)
   assert(current, "it() called outside describe()")
   table.insert(current.specs, {name = name, fn = fn})
end

local function fail(msg, level)
   error({__assert = true, msg = msg, trace = debug.getinfo((level or 2) + 1, "Sl")}, (level or 2) + 1)
end

local function render(v)
   if type(v) == "string" then return string.format("%q", v) end
   return tostring(v)
end

local function assert_equal(actual, expected, msg)
   if actual ~= expected then
      fail(("%sexpected %s, got %s"):format(msg and (msg .. ": ") or "",
         render(expected), render(actual)), 2)
   end
   return actual
end

local function assert_true(v, msg)
   if not v then fail((msg or "expected a truthy value") .. ", got " .. render(v), 2) end
   return v
end

local function assert_false(v, msg)
   if v then fail((msg or "expected a falsy value") .. ", got " .. render(v), 2) end
end

local function assert_nil(v, msg)
   if v ~= nil then fail((msg or "expected nil") .. ", got " .. render(v), 2) end
end

local function assert_match(s, pattern, msg)
   if type(s) ~= "string" or not s:find(pattern) then
      fail(("%sexpected a string matching %s, got %s"):format(msg and (msg .. ": ") or "",
         render(pattern), render(s)), 2)
   end
end

local function assert_no_match(s, pattern, msg)
   if type(s) == "string" and s:find(pattern) then
      fail(("%sexpected a string NOT matching %s, got %s"):format(msg and (msg .. ": ") or "",
         render(pattern), render(s)), 2)
   end
end

local function assert_error(fn, msg)
   local ok, err = pcall(fn)
   if ok then fail(msg or "expected the call to raise", 2) end
   return err
end

-- ---------------------------------------------------------------- reporting

local function is_file(path)
   local handle = io.open(path, "rb")
   if handle then handle:close() return true end
   return false
end

-- `dirs` may name directories or individual spec files.
local function collect_spec_files(dirs)
   local files = {}
   for _, dir in ipairs(dirs) do
      if dir:match("_spec%.lua$") and is_file(dir) then
         files[#files + 1] = dir
      else
         local pipe = io.popen("find '" .. dir:gsub("'", "'\\''") ..
            "' -name '*_spec.lua' -type f 2>/dev/null | LC_ALL=C sort")
         if pipe then
            for line in pipe:lines() do
               if line ~= "" then table.insert(files, line) end
            end
            pipe:close()
         end
      end
   end
   return files
end

local function run(dirs)
   -- Re-entrant: a spec may call run() on another directory. Keep the enclosing
   -- group's state intact so nested suites do not clobber the outer one.
   local outer_groups, outer_current = groups, current
   groups, current = {}, nil
   results = {passed = 0, failures = {}}

   for _, file in ipairs(collect_spec_files(dirs)) do
      local chunk, load_err = loadfile(file)
      if not chunk then
         table.insert(results.failures, {file = file, name = "<load>", msg = tostring(load_err)})
      else
         local ok, err = pcall(chunk)
         if not ok then
            table.insert(results.failures, {file = file, name = "<toplevel>", msg = tostring(err)})
         end
      end
   end

   for _, group in ipairs(groups) do
      io.write(group.name, "\n")
      for _, spec in ipairs(group.specs) do
         local ok, err = pcall(spec.fn)
         if ok then
            results.passed = results.passed + 1
            io.write("  ok    ", spec.name, "\n")
         else
            local msg
            if type(err) == "table" and err.__assert then
               msg = err.msg
               if err.trace then
                  msg = msg .. "\n        at " .. err.trace.short_src .. ":" .. err.trace.currentline
               end
            else
               msg = tostring(err)
            end
            table.insert(results.failures, {file = group.name, name = spec.name, msg = msg})
            io.write("  FAIL  ", spec.name, "\n")
         end
      end
   end

   io.write("\n", results.passed, " passed, ", #results.failures, " failed\n")
   for _, failure in ipairs(results.failures) do
      io.write("  FAIL [", failure.file, "] ", failure.name, "\n        ",
         (tostring(failure.msg):gsub("\n", "\n        ")), "\n")
   end

   local passed, failures = results.passed, results.failures
   groups, current = outer_groups, outer_current
   return passed, failures
end

harness.install_globals = function()
   _G.harness = harness
   for _, name in ipairs({"describe", "it", "assert_equal", "assert_true", "assert_false",
                          "assert_nil", "assert_match", "assert_no_match", "assert_error", "cli"}) do
      _G[name] = harness[name]
   end
end

harness.describe = describe
harness.it = it
harness.assert_equal = assert_equal
harness.assert_true = assert_true
harness.assert_false = assert_false
harness.assert_nil = assert_nil
harness.assert_match = assert_match
harness.assert_no_match = assert_no_match
harness.assert_error = assert_error
harness.run = run
harness.cli = nil

-- A fresh directory under TMPDIR, unique to this process. Named from the clock
-- it was not: two runs that started in the same second got the same directory
-- and deleted each other's files.
function harness.scratch_dir(tag)
   local base = (os.getenv("TMPDIR") or "/tmp"):gsub("/$", "")
   local pipe = assert(io.popen(("mktemp -d %q"):format(base .. "/luasec_" .. tag .. ".XXXXXX")))
   local dir = pipe:read("*l")
   pipe:close()
   assert(dir and dir ~= "", "mktemp -d failed for " .. tag)
   return dir
end

-- Run the CLI as a subprocess; returns combined output and the exit code.
function harness.cli(args, opts)
   opts = opts or {}
   local cmd = "./bin/luasec"
   for _, a in ipairs(args) do
      cmd = cmd .. " " .. string.format("%q", a)
   end
   if opts.stdin then
      local tmp = os.tmpname()
      local f = assert(io.open(tmp, "w"))
      f:write(opts.stdin)
      f:close()
      cmd = cmd .. " < " .. string.format("%q", tmp)
   end
   cmd = cmd .. " 2>&1; printf '\\n__EXIT__%d' $?"
   local pipe = assert(io.popen(cmd))
   local out = pipe:read("*a")
   pipe:close()
   local code = tonumber(out:match("__EXIT__(%d+)%s*$") or "-1")
   out = out:gsub("__EXIT__%d+%s*$", "")
   return out, code
end

-- Run the test runner itself in a subprocess; returns output and exit code.
-- Used to verify runner behavior without re-entering the runner in-process.
function harness.run_suite(dirs)
   local lua = os.getenv("LUA_BIN") or "./build/lua-5.4.9/src/lua"
   local cmd = string.format("%q test/run.lua", lua)
   for _, d in ipairs(dirs) do
      cmd = cmd .. " " .. string.format("%q", d)
   end
   cmd = cmd .. " 2>&1; printf '\n__EXIT__%d' $?"
   local pipe = assert(io.popen(cmd))
   local out = pipe:read("*a")
   pipe:close()
   local code = tonumber(out:match("__EXIT__(%d+)%s*$") or "-1")
   out = out:gsub("__EXIT__%d+%s*$", "")
   return out, code
end

harness.install_globals()

return harness
