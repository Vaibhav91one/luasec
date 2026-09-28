local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true, assert_match, assert_no_match =
   harness.assert_equal, harness.assert_true, harness.assert_match, harness.assert_no_match

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

describe("723: reading a sensitive path", function()
   it("reports a read of a credential or process-state path as 723", function()
      local report = fixture("sensitive_read.lua")
      local found = with_code(report, "723")
      assert_equal(#found, 3, "shadow, environ and a private key are all sensitive reads")
      local paths = {}
      for _, finding in ipairs(found) do paths[#paths + 1] = finding.path end
      table.sort(paths)
      assert_equal(table.concat(paths, " "),
         "/etc/shadow /etc/ssl/private/server.key /proc/self/environ")
   end)

   it("does not report a temp file, /etc/passwd, or a path that only contains the text", function()
      local report = fixture("clean_read.lua")
      assert_equal(#with_code(report, "723"), 0,
         "matching the text of a sensitive path is not matching the path")
   end)

   it("recognises a private key, a certificate, and another process's command line", function()
      local report = api.check_source([[
local function read()
   return io.open("/proc/1/cmdline", "r"),
          io.open("/root/.ssh/id_rsa"),
          io.open("/root/.ssh/id_rsa.pub"),
          io.open("/etc/x.pem", "rb"),
          io.open("/etc/x.p12", "rb")
end
]])
      local found = with_code(report, "723")
      assert_equal(#found, 5, "a command line and three kinds of key material are all sensitive")
      assert_equal(found[1].path, "/proc/1/cmdline", "with no mode argument the open is a read")
   end)
end)

describe("721: writing flash or firmware configuration", function()
   it("reports a write to an image partition or a boot config file as 721", function()
      local report = fixture("flash_write.lua")
      local found = with_code(report, "721")
      assert_equal(#found, 2, "a partition write and a config write are both 721")
      local paths = {}
      for _, finding in ipairs(found) do paths[#paths + 1] = finding.path end
      table.sort(paths)
      assert_equal(table.concat(paths, " "), "/dev/mtd0 /etc/config/network")
   end)

   it("does not report a temp file, a flash read, or a path below /tmp", function()
      local report = fixture("clean_write.lua")
      assert_equal(#with_code(report, "721"), 0,
         "a scratch file is not firmware state, and reading a partition is not a write")
   end)

   it("names the request source when the flash path itself is attacker controlled", function()
      local report = api.check_source([[
local function go()
   io.open("/dev/mtd" .. luci.http.formvalue("d"), "w")
   local path = "/etc/config/" .. luci.http.formvalue("f")
   local handle = io.open(path, "w")
   handle:close()
end
]], {std = "luci"})
      local found = with_code(report, "721")
      assert_equal(#found, 2, "the leading literal decides both are firmware writes")
      for _, finding in ipairs(found) do
         assert_equal(finding.source, "luci.http.formvalue",
            "the path is built from the request, including through a local")
         assert_equal(finding.confidence, "medium",
            "the class of the path is proven; the exact file is not")
      end
   end)

   it("recognises file.open only under the profile that has it", function()
      local source = [[
local function go(payload)
   local f = file.open("/dev/mtd0", "w")
   f:write(payload)
end
]]
      local with_profile = with_code(api.check_source(source, {std = "espressif"}), "721")
      assert_equal(#with_profile, 1,
         "on an ESP8266 image file.open is the flash writer, and the finding is reported once")
      assert_equal(with_profile[1].path, "/dev/mtd0")
      assert_equal(#with_code(api.check_source(source), "721"), 0,
         "without the profile there is no file library, so the name proves nothing")
   end)

   it("reports the firmware codes from the command line", function()
      local writes, write_code = harness.cli({"--std", "+openwrt",
         "test/fixtures/firmware/flash_write.lua"})
      assert_equal(write_code, 1, "a high finding makes the run exit non-zero")
      assert_match(writes, "%[721%] high: write to flash", writes)

      local reads, read_code = harness.cli({"test/fixtures/firmware/sensitive_read.lua"})
      assert_equal(read_code, 1, "a finding above the failure threshold exits non-zero")
      assert_match(reads, "%[723%] medium: sensitive file read", reads)
      assert_no_match(reads, "%[721%]", "a read of /etc/shadow is not a firmware write")
   end)
end)
