local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true = harness.assert_equal, harness.assert_true

local api = require "luasec.api"

-- Fixtures are read from disk and analyzed as source, so the file a vendor
-- would hand us is the file the spec reasons about.
local function fixture(name, opts)
   local handle = assert(io.open("test/fixtures/firmware/" .. name, "r"))
   local source = handle:read("*a")
   handle:close()
   return api.check_source(source, opts)
end

local function with_code(report, code)
   local out = {}
   for _, finding in ipairs(report) do
      if finding.code == code then out[#out + 1] = finding end
   end
   return out
end

describe("722: configuration injection through uci", function()
   it("reports a config write whose value is computed as 722, naming the config path", function()
      local report = fixture("uci_dynamic_value.lua", {std = "openwrt"})
      local found = with_code(report, "722")
      assert_equal(#found, 1, "one uci.add writes a computed value, so there is one 722")
      assert_equal(found[1].chain, "/etc/config/firewall.rule",
         "the chain is the UCI path the value can reach")
      assert_equal(found[1].name, "uci.add")
   end)

   it("names the config path of a uci.set write when only proven flows are reported", function()
      local report = fixture("uci_set_computed.lua",
         {std = "openwrt", report_dynamic_sinks = false})
      local found = with_code(report, "722")
      assert_equal(#found, 1, "the write is reported once")
      assert_equal(found[1].chain, "/etc/config/system.@system[0].hostname",
         "section and option are both literals, so the chain names all three")
   end)

   it("stays silent when every configuration value is a literal", function()
      local report = fixture("uci_literal_value.lua", {std = "openwrt"})
      assert_equal(#with_code(report, "722"), 0,
         "a value fixed in the source cannot be injected by a caller")
   end)

   it("does not add a 722 to a statement already reported as untrusted data", function()
      local report = fixture("uci_tainted_value.lua", {std = "openwrt+luci"})
      local codes = {}
      for _, finding in ipairs(report) do codes[#codes + 1] = finding.code end
      table.sort(codes)
      assert_equal(table.concat(codes, ","), "709",
         "the value comes from the request, so 722 must not be reported beside the 709")
   end)

   it("treats every declared config API as a configuration write", function()
      local report = api.check_source([[
local function go(values, name, kind)
   uci.sets("system", values)
   luci.util.uci.set("firewall", "rule", name)
   luci.util.uci.add("firewall", kind)
end
]], {std = "openwrt+luci", report_dynamic_sinks = false})
      local found = with_code(report, "722")
      assert_equal(#found, 3, "each of the three config writes carries a computed value")
      local chains = {}
      for _, finding in ipairs(found) do chains[#chains + 1] = finding.chain end
      table.sort(chains)
      assert_equal(table.concat(chains, " "),
         "/etc/config/firewall /etc/config/firewall.rule /etc/config/system")
   end)

   it("reports no configuration write when no platform profile declares one", function()
      local report = api.check_source([[
local function go(values)
   uci.sets("system", values)
   uci.set("system", "@system[0]", "hostname", values)
end
]], {report_dynamic_sinks = false})
      assert_equal(#with_code(report, "722"), 0,
         "uci is an OpenWrt API: without the profile there is no configuration to inject into")
   end)
end)
