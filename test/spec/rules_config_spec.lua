local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_match, assert_true =
   harness.assert_equal, harness.assert_match, harness.assert_true

local TAINTED = "test/fixtures/tainted_exec/handler.lua"

local function q(text) return string.format("%q", text) end

local function read(path)
   local handle = io.open(path, "rb")
   if not handle then return nil end
   local text = handle:read("*a")
   handle:close()
   return text
end

local function scratch(tag, body)
   local dir = harness.scratch_dir(tag)
   if body then
      local handle = assert(io.open(dir .. "/lua-doctor.config.lua", "w"))
      handle:write(body)
      handle:close()
   end
   return dir
end

describe("lua-doctor rules set, enable and disable", function()
   it("sets a severity in a new config, and the next scan honours it", function()
      local dir = scratch("rules_set")
      local out, code = harness.cli({"rules", "set", "709", "low", "--config", dir .. "/lua-doctor.config.lua"})
      assert_equal(code, 0, out)
      assert_match(out, "wrote .*lua%-doctor%.config%.lua: 709 %-> low", out)
      local scan = harness.cli({"--config", dir .. "/lua-doctor.config.lua", TAINTED})
      os.execute("rm -rf " .. q(dir))
      assert_match(scan, "%[709%] low", scan)
   end)

   it("disables and re-enables a code", function()
      local dir = scratch("rules_disable")
      local file = dir .. "/lua-doctor.config.lua"
      harness.cli({"rules", "disable", "709", "--config", file})
      local off = harness.cli({"--config", file, TAINTED})
      assert_true(not off:find("[709]", 1, true), "disabled: " .. off)
      harness.cli({"rules", "enable", "709", "--config", file})
      local on = harness.cli({"--config", file, TAINTED})
      os.execute("rm -rf " .. q(dir))
      assert_match(on, "%[709%]", on)
   end)

   it("keeps what else the config says", function()
      local dir = scratch("rules_keep", 'return {\n  std = "+openwrt+luci",\n  fail_on = "high",\n}\n')
      local file = dir .. "/lua-doctor.config.lua"
      harness.cli({"rules", "set", "701", "medium", "--config", file})
      local text = read(file)
      os.execute("rm -rf " .. q(dir))
      assert_match(text, 'std = "%+openwrt%+luci"', text)
      assert_match(text, 'fail_on = "high"', text)
      assert_match(text, '%["701"%] = "medium"', text)
   end)

   it("refuses a code that does not exist and a severity that does not exist", function()
      local dir = scratch("rules_bad")
      local file = dir .. "/lua-doctor.config.lua"
      local a, a_code = harness.cli({"rules", "set", "799", "low", "--config", file})
      local b, b_code = harness.cli({"rules", "set", "709", "urgent", "--config", file})
      local made = read(file)
      os.execute("rm -rf " .. q(dir))
      assert_equal(a_code, 2, a)
      assert_match(a, "unknown code '799'", a)
      assert_equal(b_code, 2, b)
      assert_match(b, "expected off, low, medium, high or critical", b)
      assert_equal(made, nil, "nothing was written")
   end)

   it("will not rewrite a config that has comments, and says what to add", function()
      local body = "-- our settings\nreturn {\n  fail_on = \"high\",\n}\n"
      local dir = scratch("rules_comment", body)
      local file = dir .. "/lua-doctor.config.lua"
      local out, code = harness.cli({"rules", "set", "709", "low", "--config", file})
      local after = read(file)
      os.execute("rm -rf " .. q(dir))
      assert_equal(code, 2, out)
      assert_match(out, "comments that a rewrite would lose", out)
      assert_match(out, 'severity = {%["709"%] = "low"},', out)
      assert_equal(after, body, "the file is untouched")
   end)
end)
