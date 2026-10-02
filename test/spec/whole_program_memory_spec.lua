-- Whole-program analysis holds every file's analysis until the cross-file pass,
-- so its memory grows with the tree. It must grow linearly: the live heap at the
-- start of the cross-file pass for 4N files is held to under 8x the heap for N
-- (linear gives about 4, quadratic about 16), the same loose ratio
-- performance_spec uses, so the bound is independent of the machine (#197).
local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_true = harness.assert_true

local api = require "luasec.api"

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

-- The live heap, in kB above where it started, when every file is held and the
-- cross-file pass begins.
local function held_kb(count)
   local dir, paths = tree(count)
   collectgarbage("collect")
   local base = collectgarbage("count")
   local held = 0
   api.analyze(paths, {whole_program = true, on_phase = function()
      collectgarbage("collect")
      held = collectgarbage("count") - base
   end})
   os.execute(("rm -rf %q"):format(dir))
   return held
end

describe("whole-program memory", function()
   it("grows linearly with the number of files held for the cross-file pass", function()
      local small = held_kb(12)
      local large = held_kb(48)
      assert_true(small > 0, "nothing was measured for 12 files")
      local ratio = large / small
      assert_true(ratio < 8, ("held %.0f kB for 48 files against %.0f kB for 12: ratio %.1f, not linear")
         :format(large, small, ratio))
   end)
end)
