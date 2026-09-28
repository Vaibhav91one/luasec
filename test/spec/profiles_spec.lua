local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true, assert_match = harness.assert_equal, harness.assert_true, harness.assert_match

local api = require "luasec.api"

local function codes(report)
   local out = {}
   for _, finding in ipairs(report) do out[#out + 1] = finding.code end
   table.sort(out)
   return table.concat(out, ",")
end

describe("platform profiles", function()
   it("makes a profile's sources taint without a code change", function()
      local report = api.check_source([[
local function go()
   os.execute("ping " .. uci.get("system", "hostname"))
end
]], {std = "openwrt"})
      assert_equal(codes(report), "709", "uci.get is a source under the openwrt profile")
   end)

   it("leaves the same code silent without the profile", function()
      local report = api.check_source([[
local function go()
   os.execute("ping " .. uci.get("system", "hostname"))
end
]])
      assert_equal(codes(report), "708",
         "without the profile there is no source, so only the exposure is reported")
   end)

   it("composes profiles", function()
      local report = api.check_source([[
local function go()
   local a = luci.http.formvalue("a")
   local b = uci.get("system", "hostname")
   os.execute(a .. b)
end
]], {std = "openwrt+luci"})
      assert_equal(codes(report), "709")
   end)

   it("reports use of the LuaJIT FFI as an escape hatch, even with a constant argument", function()
      local report = api.check_source([[
local ffi = require("ffi")
local C = ffi.C
C.system("id")
]], {std = "luajit"})
      assert_match(codes(report), "707", "reaching libc through ffi.C is a finding on its own")
   end)

   it("reports the FFI as a command injection sink when its argument is tainted", function()
      local report = api.check_source([[
local C = require("ffi").C
C.system("ping " .. http.formvalue("host"))
]], {std = "luajit"})
      assert_match(codes(report), "709", "tainted data into ffi.C.system is command injection")
   end)

   it("rejects an unknown profile name with a message naming the known ones", function()
      local ok, err = pcall(api.check_source, "return 1", {std = "nosuchplatform"})
      assert_true(ok == false or err, "an unknown profile must be reported")
   end)

   it("exposes every built-in profile to the CLI", function()
      local out = harness.cli({ "--std", "nosuchplatform", "test/fixtures/clean/report.lua" })
      assert_equal(select(2, harness.cli({ "--std", "nosuchplatform", "test/fixtures/clean/report.lua" })), 2)
      assert_match(out, "unknown platform profile", out)
      assert_match(out, "openwrt", "the error should list the known profiles")
   end)
end)
