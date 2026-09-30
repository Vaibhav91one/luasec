local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true, assert_match = harness.assert_equal, harness.assert_true, harness.assert_match

local api = require "luasec.api"
local profiles = require "luasec.registry.profiles"

local function codes(report)
   local out = {}
   for _, finding in ipairs(report) do out[#out + 1] = finding.code end
   table.sort(out)
   return table.concat(out, ",")
end

local function sources_of(report, code)
   local out = {}
   for _, finding in ipairs(report) do
      if finding.code == code then out[#out + 1] = finding.source end
   end
   return out
end

describe("cgilua profile", function()
   it("flags request data from the global cgi table reaching os.execute", function()
      local report = api.check_source([[
os.execute("ping " .. cgi["host"])
]], {std = "cgilua"})
      assert_equal(codes(report), "709")
      assert_equal(sources_of(report, "709")[1], "cgi")
   end)

   it("leaves the same global read silent without the std", function()
      local report = api.check_source([[
os.execute("ping " .. cgi["host"])
]])
      assert_true(not codes(report):match("709"), "no 709 without the std, got " .. codes(report))
   end)

   it("flags cgiToLuaTable output reaching the vendor exec wrapper", function()
      local report = api.check_source([[
local t = web.cgiToLuaTable(cgi)
util.runShellCmd("x " .. t.name)
]], {std = "cgilua"})
      assert_equal(codes(report), "709")
   end)

   it("does not treat a local named cgi as a source", function()
      local report = api.check_source([[
local cgi = "fixed"
os.execute("ping " .. cgi)
]], {std = "cgilua"})
      assert_true(not codes(report):match("709"), "local cgi must not taint, got " .. codes(report))
   end)

   it("flags an assigned cgiToLuaTable result reaching os.execute", function()
      local report = api.check_source([[
inputTable = web.cgiToLuaTable(cgi)
os.execute(inputTable.x)
]], {std = "cgilua"})
      assert_equal(codes(report), "709")
   end)

   it("flags RowId reaching os.execute only under the std", function()
      local with = api.check_source([[
os.execute("id " .. RowId)
]], {std = "cgilua"})
      assert_equal(codes(with), "709")
      local without = api.check_source([[
os.execute("id " .. RowId)
]])
      assert_true(not codes(without):match("709"), "RowId silent without std, got " .. codes(without))
   end)

   it("leaves a constant vendor wrapper call silent", function()
      local report = api.check_source([[
util.shellCmdOutput("uptime")
]], {std = "cgilua"})
      assert_equal(codes(report), "")
   end)

   it("scans the cgilua page fixture through the vendor wrapper", function()
      local fh = assert(io.open("test/fixtures/cgilua/page.lua", "r"))
      local src = fh:read("*a")
      fh:close()
      local report = api.check_source(src, {std = "cgilua"})
      assert_match(codes(report), "709")
   end)

   it("composes cgilua with openwrt", function()
      local names, add = profiles.split("cgilua+openwrt")
      assert_equal(table.concat(names, ","), "cgilua,openwrt")
      local report = api.check_source([[
os.execute("ping " .. cgi["host"])
]], {std = "cgilua+openwrt"})
      assert_match(codes(report), "709")
   end)

   it("does not leak the global source into a later run without the std", function()
      api.check_source([[os.execute("ping " .. cgi["host"])]], {std = "cgilua"})
      local report = api.check_source([[os.execute("ping " .. cgi["host"])]])
      assert_true(not codes(report):match("709"), "global source leaked, got " .. codes(report))
   end)
end)
