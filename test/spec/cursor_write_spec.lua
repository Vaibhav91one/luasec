-- #317: a value written through a UCI cursor handle (`c:set(...)`) is a 722 only
-- when request data reaches it. The literal `uci.set` form reports a merely
-- computed value too; a cursor write with a constant or computed value is the
-- normal case in firmware and stays quiet.
local harness = require "harness"
local describe, it, assert_equal = harness.describe, harness.it, harness.assert_equal

local api = require "luasec.api"

local function codes_of(source)
   local out = {}
   for _, finding in ipairs(api.check_source(source, {std = "openwrt+luci"})) do
      if finding.code == "722" then out[#out + 1] = finding end
   end
   return out
end

describe("722: a write through a cursor handle needs tainted data (#317)", function()
   it("reports a request value written with c:set", function()
      local found = codes_of([[
local uci = require("luci.model.uci")
local c = uci.cursor()
c:set("system", "@system[0]", "hostname", luci.http.formvalue("h"))
]])
      assert_equal(#found, 1, "the request parameter reaches the config")
      assert_equal(found[1].name, "uci:set")
   end)

   it("reports a tainted section value and a tainted tset table", function()
      local found = codes_of([[
local c = require("uci").cursor()
local v = luci.http.formvalue("v")
c:section("firewall", "rule", nil, {src = v})
c:tset("firewall", "cfg1", {dest = v})
]])
      assert_equal(#found, 2, "section values and tset values are written values")
   end)

   it("follows a function that returns the cursor", function()
      local found = codes_of([[
local function open() return require("uci").cursor() end
local c = open()
c:set("a", "b", "c", luci.http.formvalue("x"))
]])
      assert_equal(#found, 1, "the factory is a handle, as for 747")
   end)

   it("does not report a constant value", function()
      assert_equal(#codes_of([[
local c = require("uci").cursor()
c:set("system", "@system[0]", "hostname", "router")
c:section("firewall", "rule", nil, {src = "lan"})
]]), 0, "a value fixed in the source cannot be injected")
   end)

   it("does not report a computed value that no request data reaches", function()
      assert_equal(#codes_of([[
local c = require("uci").cursor()
local stamp = "t" .. tostring(os.time())
c:set("system", "@system[0]", "note", stamp)
c:set("system", "@system[0]", "id", "pre-" .. #arg .. stamp)
c:section("firewall", "rule", nil, {name = stamp})
]]), 0, "computed is not tainted; only request data makes a 722")
   end)

   it("does not take another object's :set for a config write", function()
      assert_equal(#codes_of([[
local db = open_database()
db:set("a", "b", "c", luci.http.formvalue("x"))
]]), 0, "db is not a cursor")
   end)

   it("does not report a tainted section or config name", function()
      assert_equal(#codes_of([[
local c = require("uci").cursor()
c:section("firewall", "rule", luci.http.formvalue("name"), {src = "lan"})
]]), 0, "a section name is not a written value")
   end)
end)
