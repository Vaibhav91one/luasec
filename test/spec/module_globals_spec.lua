local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true = harness.assert_equal, harness.assert_true

-- Loading lua-doctor's modules must not add anything to _G.
--
-- A global that a module defines on load is invisible everywhere: `make
-- selfscan` runs lua-doctor over src/ and lua-doctor has no rule for it, so the function
-- works, the build is green, and the leak ships. That is how `callee_path`
-- reached a release as a global (#277).
--
-- This is the belt to the lint's braces. The lint reads a tool's configuration
-- and can be turned off, narrowed or mis-pointed; this reads only what running
-- the code does. It needs no linter, no config file and no vendored dependency,
-- and it fails on a leak in a file luacheck was never pointed at.
--
-- It runs in a fresh interpreter, not in this one. Requiring every module in
-- this process would leave all of them in package.loaded for the specs that
-- run afterwards, which is a different test suite than the one that ran before
-- and a leak could hide behind whichever module happened to load first.
local PROBE = [==[
local function lua_files(dir, acc)
   local pipe = io.popen(("ls -1F %q"):format(dir))
   if not pipe then return acc end
   for line in pipe:lines() do
      local is_dir = line:sub(-1) == "/"
      local name = is_dir and line:sub(1, -2) or line
      local path = dir .. "/" .. name
      if is_dir then
         lua_files(path, acc)
      elseif path:sub(-4) == ".lua" then
         acc[#acc + 1] = path
      end
   end
   pipe:close()
   return acc
end

package.path = "./src/?.lua;./src/?/init.lua;./vendor/?.lua;./vendor/?/init.lua;" .. package.path

local files = lua_files("src/luasec", {})
table.sort(files)

local before = {}
for name in pairs(_G) do before[name] = true end

local failed, skipped, loaded = {}, {}, 0
for _, path in ipairs(files) do
   -- src/luasec/foo/bar.lua is require "lua-doctor.foo.bar".
   local module_name = path:gsub("^src/", ""):gsub("%.lua$", ""):gsub("/init$", ""):gsub("/", ".")
   if module_name == "luasec.main" then
      -- The CLI entry point ends in `os.exit(run(arg))`, so requiring it parses
      -- a command line and leaves the process. It is the one file under src/
      -- that is not a module, and it is the one file this check cannot load.
      skipped[#skipped + 1] = module_name
   else
      local ok, err = pcall(require, module_name)
      if ok then
         loaded = loaded + 1
      else
         failed[#failed + 1] = module_name .. ": " .. tostring(err)
      end
   end
end

assert(#failed == 0, "these modules would not load: " .. table.concat(failed, "; "))

local gained = {}
for name in pairs(_G) do
   if not before[name] then gained[#gained + 1] = name end
end
table.sort(gained)

io.write("modules ", loaded, "\n")
for _, name in ipairs(gained) do io.write("global ", name, "\n") end
]==]

-- Globals lua-doctor's modules add to _G today. This is a ratchet, not an
-- endorsement: every entry below is a real leak, and none of them was caught
-- before #277 added this spec.
--
-- A leak here is a missing `local`. One of them was not even an accident:
-- `validate/child.lua` is not a module at all - the driver reads the file and
-- concatenates it in front of the payload to build a one-shot `lua -e` program,
-- so the two halves can only meet through globals. That is a deliberate design
-- and it is the reason the file is allowed here rather than fixed.
--
-- Remove the `local` and delete the line. Do not add to this list: the next one
-- is the bug this spec exists for.
local EXPECTED = {
   ["__luasec_emit"] = "validate/child.lua: the driver and the sandbox child are one concatenated program",
   ["__luasec_sandbox"] = "validate/child.lua: the driver and the sandbox child are one concatenated program",
   ["line_len_available"] = "engine/parse_context.lua: missing `local` on the function at line 178",
   ["read_attribute"] = "rules/rawscan.lua: missing `local` on the function at line 542",
   ["read_require_module"] = "rules/rawscan.lua: missing `local` on the function at line 556",
   ["resolve_standard"] = "rules/rawscan.lua: missing `local` on the function at line 140",
}

local function run_probe()
   local dir = harness.scratch_dir("globals")
   local script = dir .. "/probe.lua"
   local handle = assert(io.open(script, "w"))
   handle:write(PROBE)
   handle:close()

   local lua = os.getenv("LUA_BIN") or "./build/lua-5.4.9/src/lua"
   local pipe = assert(io.popen(("%s %s 2>&1; printf '\\n__EXIT__%%d' $?"):format(
      string.format("%q", lua), string.format("%q", script))))
   local out = pipe:read("*a")
   pipe:close()

   local code = tonumber(out:match("__EXIT__(%d+)%s*$") or "-1")
   -- A `require` that fails prints every path it tried, which is a hundred lines
   -- of noise around the one line that says why.
   assert_equal(code, 0, "the probe interpreter failed:\n" .. out:sub(1, 600))

   local modules, gained = tonumber(out:match("modules (%d+)") or "0"), {}
   for name in out:gmatch("global ([^\n]+)") do gained[#gained + 1] = name end
   return modules, gained
end

describe("module load", function()
   it("loads every lua-doctor module, so a walk that finds nothing cannot pass", function()
      local modules = run_probe()
      assert_true(modules > 1,
         ("expected the probe to load lua-doctor's modules, it loaded %d"):format(modules))
   end)

   it("defines no global", function()
      local modules, gained = run_probe()
      local seen, leaked, fixed = {}, {}, {}
      for _, name in ipairs(gained) do
         seen[name] = true
         if not EXPECTED[name] then
            leaked[#leaked + 1] = ("'%s' becomes a global when its module is loaded "
               .. "and is not on the list this spec knows about; add `local` where it is "
               .. "defined rather than adding it to the list"):format(name)
         end
      end
      for name in pairs(EXPECTED) do
         if not seen[name] then
            fixed[#fixed + 1] = ("'%s' no longer becomes a global (%d modules loaded): the "
               .. "leak is gone, so delete its line from the list in this spec")
               :format(name, modules)
         end
      end
      assert_equal(#leaked, 0, table.concat(leaked, "\n"))
      assert_equal(#fixed, 0, table.concat(fixed, "\n"))
   end)
end)