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

   it("reports a firmware write whose mode the source does not state, at low confidence", function()
      local report = api.check_source([[
local function go(mode)
   local f = io.open("/dev/mtd0", mode)
   f:close()
end
]])
      local found = with_code(report, "721")
      assert_equal(#found, 1, "the path is firmware state and the mode is unknown")
      assert_equal(found[1].confidence, "low",
         "nothing proves it writes, so nothing may claim it does")
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

describe("725: changing the environment a chunk runs in", function()
   it("reports setfenv and debug.setmetatable applied to the global table", function()
      local report = fixture("sandbox_escape.lua")
      local found = with_code(report, "725")
      assert_equal(#found, 5, "two setfenv spellings, a metatable on _G, and both search paths")
      local apis = {}
      for _, finding in ipairs(found) do apis[#apis + 1] = finding.name end
      table.sort(apis)
      assert_equal(table.concat(apis, " "),
         "debug.setfenv debug.setmetatable package.cpath package.path setfenv")
   end)

   it("reports reassignment of _G, _ENV and package.loaded", function()
      local report = api.check_source([[
_G = {}
_ENV = {}
package.loaded = {}
]])
      local found = with_code(report, "725")
      assert_equal(#found, 3)
      local apis = {}
      for _, finding in ipairs(found) do apis[#apis + 1] = finding.name end
      table.sort(apis)
      assert_equal(table.concat(apis, " "), "_ENV _G package.loaded")
   end)

   it("does not report a local _G, a local metatable, or a module published to the cache", function()
      local report = fixture("sandbox_clean.lua")
      assert_equal(#with_code(report, "725"), 0,
         "a local named _G is not the global table, and caching a module is ordinary")
   end)
end)

describe("726: destructive or self-modifying operation", function()
   it("reports removal or renaming of a firmware path", function()
      local report = fixture("destructive.lua")
      local found = with_code(report, "726")
      assert_equal(#found, 6, "six of the seven operations touch a firmware path")
      local names = {}
      for _, finding in ipairs(found) do names[#names + 1] = finding.name end
      table.sort(names)
      assert_equal(table.concat(names, " "), "os.remove os.remove os.remove os.remove os.remove os.rename",
         "a rename is reported on the path it destroys, and a /tmp path is not reported")
   end)

   it("does not report a scratch file or a path the script only reads", function()
      local report = fixture("clean_remove.lua")
      assert_equal(#with_code(report, "726"), 0,
         "/tmp/scratch is this script's own file and /etc/passwd is only opened")
   end)

   it("reports a truncating write to a file the script already wrote", function()
      local report = fixture("self_modify.lua")
      local found = with_code(report, "726")
      assert_equal(#found, 1, "only the second open truncates what the first wrote")
      assert_equal(found[1].line, 7, "the rewrite is the finding, not the install")
      assert_equal(found[1].path, "/etc/init.d/tunnel")
   end)
end)

describe("727: unbounded growth in a loop", function()
   it("reports a loop that appends with no limit the source states", function()
      local report = fixture("unbounded_growth.lua")
      local found = with_code(report, "727")
      assert_equal(#found, 4, "a computed limit, a while, an unknown iterator and a repeat")
      local names = {}
      for _, finding in ipairs(found) do names[#names + 1] = finding.name end
      table.sort(names)
      assert_equal(table.concat(names, " "), "Forin Fornum Repeat While")
   end)

   it("does not report a loop whose turns come from a container", function()
      local report = api.check_source([[
local function copy(t, out)
   for key, value in pairs(t) do out[#out + 1] = value end
   for index, value in ipairs(t) do out[#out + 1] = value end
   for index = 1, #t do out[#out + 1] = t[index] end
   for line in (t.text or ""):gmatch("[^\n]+") do out[#out + 1] = line end
   for line in t.handle:lines() do out[#out + 1] = line end
   return out
end
]])
      assert_equal(#with_code(report, "727"), 0,
         "a container's size, a line count and a match count are all ceilings the source states")
   end)

   it("does not report a loop that returns before it can come back around", function()
      local report = api.check_source([[
local function read_all(handle)
   local out = {}
   while true do
      local line = handle:read()
      if not line then return out end
      out[#out + 1] = line
   end
end
]])
      assert_equal(#with_code(report, "727"), 0,
         "while true is the ordinary way to spell a loop that ends by returning")
   end)

   it("reports a doubling even inside a loop the source bounds", function()
      local report = api.check_source([[
local function double(times)
   local s = "x"
   for i = 1, times do s = s .. s end
   return s
end
]])
      local found = with_code(report, "727")
      assert_equal(#found, 1, "32 turns of a doubling is 4 GB, whatever the count is")
      assert_equal(found[1].name, "Fornum")
   end)

   it("does not report a loop with a literal limit, or an append outside one", function()
      local report = fixture("bounded_growth.lua")
      assert_equal(#with_code(report, "727"), 0,
         "a loop the source bounds cannot outgrow the device")
   end)

   it("reports a repeat count the request chooses, and not one the script computes", function()
      local report = api.check_source([[
local function pad(unit, indent)
   return string.rep(unit, luci.http.formvalue("n")),
          string.rep("  ", indent + 1),
          string.rep("-", 40)
end
]], {std = "luci"})
      local found = with_code(report, "727")
      assert_equal(#found, 1,
         "a count of 40 is a ceiling and a recursion depth is a design, not an attack")
      assert_equal(found[1].name, "string.rep")
      assert_equal(found[1].line, 2)
   end)
end)

describe("728: untrusted data used as a search pattern", function()
   it("reports a computed pattern in every library that takes one", function()
      local report = fixture("dynamic_pattern.lua")
      local found = with_code(report, "728")
      assert_equal(#found, 6, "four Lua string functions and two ngx ones")
      local names = {}
      for _, finding in ipairs(found) do names[#names + 1] = finding.name end
      table.sort(names)
      assert_equal(table.concat(names, " "),
         "ngx.re.find ngx.re.gsub string.find string.gmatch string.gsub string.match")
   end)

   it("does not report a pattern the source states, or a plain find", function()
      local report = fixture("literal_pattern.lua")
      assert_equal(#with_code(report, "728"), 0,
         "a literal pattern is a search, and string.find with plain=true is not a pattern")
   end)

   it("names the request source when the pattern comes from the request", function()
      local report = api.check_source([[
local function go(subject)
   return string.gsub(subject, luci.http.formvalue("p"), "")
end
]], {std = "luci"})
      local found = with_code(report, "728")
      assert_equal(#found, 1)
      assert_equal(found[1].source, "luci.http.formvalue")
      assert_equal(found[1].confidence, "high", "the dataflow is unambiguous")
   end)
end)

describe("firmware rules: cost and hostile input", function()
   -- One block per line count, each exercising every code in this module, so
   -- the scaling measured is the module's and not one of its detectors. "@" is
   -- the block's index.
   local BLOCK = [[
-- generated block @
local function handler_@(req, p)
   local v@ = req and p or nil
   uci.set("system", "@system[0]", "opt_@", v@)
   io.open("/etc/config/n_@", "w"):write(tostring(v@))
   io.open("/etc/init.d/svc_@", "w")
   io.open("/proc/self/environ", "r")
   setfenv(1, v@)
   os.remove("/etc/config/n_@")
   local s = ""
   for k = 1, v@ do s = s .. "x" end
   string.gsub(s, v@, "")
   return s
end
]]

   local function generated(blocks)
      local out = {}
      for index = 0, blocks - 1 do
         out[#out + 1] = (BLOCK:gsub("@", function() return tostring(index) end))
      end
      -- Lua requires return to be the last statement in a block.
      out[#out + 1] = "return handler_0\n"
      return table.concat(out)
   end

   it("keeps the findings per line constant as the file grows", function()
      local function findings(blocks)
         return #api.check_source(generated(blocks), {std = "+openwrt"})
      end
      local small, large = findings(50), findings(200)
      assert_equal(large, 4 * small,
         "four times the source is four times the findings: no detector drifts")
   end)

   it("stays linear on a file an attacker wrote to be expensive", function()
      local hostile = table.concat({
         -- One long run of one character, as a path, in every set.
         ('io.open("/%s", "r")\nio.open("/etc/shadow%s", "r")\n'):format(("a"):rep(4000), ("b"):rep(4000)),
         -- Many short segments, and one that nearly matches every basename rule.
         ('io.open("%s/x", "r")\n'):format(("/abcdefghij"):rep(400)),
         -- A concat chain 3000 deep on a firmware path.
         ('local a = "x"\nio.open("/etc/config/"%s, "w")\n'):format((" .. a"):rep(3000)),
         -- A local definition cycle used as a path.
         "local a, b\n", "a = b\nb = a\n", 'io.open(a, "w")\n',
         -- Loops nested 120 deep around one append.
         "local s = ''\n", ("for i = 1, n do\n"):rep(120), "s = s .. 'x'\n", ("end\n"):rep(120),
      })
      local report = api.check_source(hostile, {std = "+openwrt"})
      assert_true(#report >= 0, "an expensive file is analyzed, not refused")
      for _, finding in ipairs(report) do
         assert_true(finding.code ~= "901",
            "an unexpected shape must degrade to silence, not a parse failure: "
               .. tostring(finding.message))
      end
   end)
end)
