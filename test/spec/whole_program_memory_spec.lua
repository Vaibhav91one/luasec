-- Whole-program analysis holds every file's analysis until the cross-file pass,
-- so its memory grows with the tree and must grow no faster than the tree.
--
-- The bound is an ABSOLUTE one, on the kB held per file, not the ratio of two
-- measurements (#251). A ratio needs a denominator, and a denominator measured
-- in this process is a number every other spec in the run can move: the same
-- measurement read 402 kB for 12 files in a fresh process and 113 kB after the
-- rest of the suite had run, which turned a perfectly healthy 3.98 into 14.2
-- and failed the suite for something that had nothing to do with the analyzer.
-- A ratio also cannot see a regression that scales both figures at once, which
-- is the ordinary kind: at a deliberate 1.9x the old spec here passed, because
-- 1.9 x 3.98 is 3.98. Per file, the two do not cancel - doubling what is held
-- doubles what one file costs, and the bound catches that.
--
-- What that costs, stated plainly because the old header claimed otherwise:
-- this bound is NOT independent of the machine, and no longer claims to be. It
-- is a figure in kB calibrated against the pinned Lua 5.4.9 this repo builds,
-- so it would have to be re-measured if the interpreter changed. What it IS
-- independent of is everything that moved the old number: the machine's speed,
-- and whatever the rest of the suite left on the heap. The figure is a
-- deterministic count of the bytes a parse actually allocated, not a timing -
-- it read 33.4 per file at every size from 12 files to 192, and the 48-file
-- figure GitHub Actions printed when this went wrong is the same to the byte -
-- so the headroom below is headroom against a change in the analyzer, which is
-- the only thing it is there to catch.
--
-- The figure is read in a fresh process, because the value this spec measures -
-- the live heap at the cross-file pass, minus the live heap before it - is the
-- value that another spec perturbs. Nothing else in the run runs in the process
-- that takes the reading, so nothing else in the run can reach it.
local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_true, assert_false = harness.assert_true, harness.assert_false

-- The interpreter running this suite, and the package.path the Makefile gives
-- it, so the measuring process resolves luasec exactly as this process did.
local PACKAGE_PATH = table.concat({"./src/?.lua", "./src/?/init.lua",
   "./vendor/?.lua", "./vendor/?/init.lua"}, ";") .. ";"
local LUA_RUN = "./build/lua-5.4.9/src/lua -e 'package.path=\"" .. PACKAGE_PATH .. "\"..package.path'"

-- Files held across the cross-file pass. 48 is where a whole-program scan is
-- already doing real work; the per-file figure does not move with the count.
local FILES = 48

-- The bound: kB held per file, at FILES files. The analysis measures 33.4, so
-- this is 1.5x the measured figure - loose enough that the reading is never
-- what turns the spec red, and tight enough that twice the measured figure
-- (66.8) is over it. A quadratic cross-file pass costs four times as much per
-- file at this size, which is well over it too.
local MAX_KB_PER_FILE = 50

-- `count` modules, each requiring the one before it and passing its argument on.
local function tree(count)
   local dir = harness.scratch_dir("wp_memory")
   local paths = {}
   for index = 1, count do
      local path = ("%s/m%03d.lua"):format(dir, index)
      local handle = assert(io.open(path, "w"))
      local previous = index > 1 and ("local prev = require \"m%03d\"\n"):format(index - 1) or ""
      handle:write(previous, "local M = {}\n",
         "function M.run(cfg)\n",
         "   local parts = {}\n",
         "   for key, value in pairs(cfg) do parts[#parts + 1] = key .. '=' .. tostring(value) end\n",
         index > 1 and "   prev.run(cfg)\n" or "   os.execute('x ' .. table.concat(parts, ' '))\n",
         "   return table.concat(parts, ',')\n",
         "end\nreturn M\n")
      handle:close()
      paths[#paths + 1] = path
   end
   return dir, paths
end

-- What the measuring process runs. It is the whole measurement, and it runs
-- nowhere else: a process that has analyzed nothing has no history to be
-- carrying, which is the whole point.
local DRIVER = [[
local api = require "luasec.api"
local paths = {}
for line in io.lines(arg[1]) do paths[#paths + 1] = line end

collectgarbage("collect")
local base = collectgarbage("count")
local held = 0
api.analyze(paths, {whole_program = true, on_phase = function()
   collectgarbage("collect")
   held = collectgarbage("count") - base
end})
-- collectgarbage("count") already reports kilobytes, not bytes.
io.write(("%.4f\n"):format(held / #paths))
]]

-- The kB per file held across the cross-file pass for `count` files, measured
-- in a fresh process that has run nothing else.
local function held_kb_per_file(count)
   local dir, paths = tree(count)
   local work = harness.scratch_dir("wp_memory_probe")
   local handle = assert(io.open(work .. "/paths", "w"))
   handle:write(table.concat(paths, "\n"), "\n")
   handle:close()
   handle = assert(io.open(work .. "/held.lua", "w"))
   handle:write(DRIVER)
   handle:close()
   local command = ("%s %q %q 2>&1"):format(LUA_RUN, work .. "/held.lua", work .. "/paths")
   local pipe = assert(io.popen(command))
   local out = pipe:read("*a")
   local ran = pipe:close()
   os.execute(("rm -rf %q"):format(dir))
   os.execute(("rm -rf %q"):format(work))
   assert_true(ran, "the measuring process failed:\n" .. out)
   local kb = tonumber(out)
   assert_true(kb, "the measuring process reported no held figure, only:\n" .. out)
   return kb
end

-- The decision the bound makes, named so the next spec can make it too.
local function within_bound(kb_per_file)
   return kb_per_file <= MAX_KB_PER_FILE
end

-- Taken once and shared: both specs below are about the same reading.
local reading
local function measured()
   reading = reading or held_kb_per_file(FILES)
   return reading
end

describe("whole-program memory", function()
   it("holds no more than the bound for each file kept for the cross-file pass", function()
      local kb = measured()
      assert_true(kb > 0, "nothing was held for " .. FILES .. " files")
      assert_true(within_bound(kb), ("held %.1f kB per file across %d files, over the %.0f kB bound")
         :format(kb, FILES, MAX_KB_PER_FILE))
   end)

   it("rejects a held-memory regression that doubles what one file costs", function()
      -- The defence against a fix that stops measuring: if the bound were ever
      -- loosened far enough to let a doubled analyzer through, it would have to
      -- take twice what it measures today, and this is the assertion that says
      -- so. Anchored to the reading rather than to the bound, so raising the
      -- bound to cover a 2x regression is what turns this red - and so a
      -- measurement that stops measuring anything, and reads near zero, fails
      -- here too rather than passing the bound above.
      local doubled = measured() * 2
      assert_false(within_bound(doubled), ("a 2x regression reads %.1f kB per file and the bound must reject it")
         :format(doubled))
   end)
end)
