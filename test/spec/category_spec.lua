local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_match, assert_true =
   harness.assert_equal, harness.assert_match, harness.assert_true

local TAINTED = "test/fixtures/tainted_exec/handler.lua"

describe("--category", function()
   it("keeps one family of codes", function()
      local out, code = harness.cli({"--category", "exec", TAINTED})
      assert_equal(code, 1, out)
      assert_match(out, "%[709%]", out)
      local none, none_code = harness.cli({"--category", "firmware", TAINTED})
      assert_equal(none_code, 0, none)
      assert_true(not none:find("[709]", 1, true), none)
   end)

   it("takes several, comma separated or repeated", function()
      local a = harness.cli({"--category", "firmware,exec", TAINTED})
      local b = harness.cli({"--category", "firmware", "--category", "exec", TAINTED})
      assert_match(a, "%[709%]", a)
      assert_equal(a, b, "the two spellings agree")
   end)

   it("never hides a file that was not analysed", function()
      local dir = harness.scratch_dir("category_gap")
      local handle = assert(io.open(dir .. "/broken.lua", "w"))
      handle:write("x = !\n")
      handle:close()
      local out, code = harness.cli({"--category", "firmware", dir .. "/broken.lua"})
      os.execute("rm -rf " .. string.format("%q", dir))
      assert_equal(code, 1, out)
      assert_match(out, "%[901%]", out)
   end)

   it("refuses a family that does not exist", function()
      local out, code = harness.cli({"--category", "network", TAINTED})
      assert_equal(code, 2, out)
      assert_match(out, "%-%-category expects one of exec, firmware, payload, artifact, meta", out)
   end)
end)
