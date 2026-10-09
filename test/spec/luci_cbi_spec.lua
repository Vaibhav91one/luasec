-- LuCI CBI models read the posted form through `field:formvalue(section)`, and
-- call `field.validate(self, value, section)` / `field.write(self, section,
-- value)` with it. A dispatcher target forwarding `...` to a helper hands that
-- helper the URL path segments. All of it is request data (#309).
local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_true, assert_equal = harness.assert_true, harness.assert_equal

local api = require "luasec.api"

local function luci_file(tag, subdir, name, body)
   local dir = harness.scratch_dir(tag) .. "/root/usr/lib/lua/luci/" .. subdir
   os.execute(("mkdir -p %q"):format(dir))
   local path = dir .. "/" .. name
   local handle = assert(io.open(path, "w"))
   handle:write(body)
   handle:close()
   return path
end

local function scan(subdir, body)
   local path = luci_file("luci_cbi", subdir, "m.lua", body)
   return api.analyze({path}, {std = "luci"})
end

local function find(report, code)
   for _, finding in ipairs(report) do
      if finding.code == code then return finding end
   end
end

describe("luci CBI sources", function()
   it("reports a field:formvalue(section) value reaching luci.sys.call as 709", function()
      local report = scan("model/cbi", [[
local ip = s:option(Value, "ip")
function ip.parse(self, section)
   local v = ip:formvalue(section)
   luci.sys.call("ping " .. v)
end
]])
      local finding = find(report, "709")
      assert_true(finding ~= nil, "expected a 709")
      assert_equal("luci.cbi.formvalue", finding.source)
   end)

   it("reports a CBI validate callback's value reaching a command as 709", function()
      local report = scan("model/cbi", [[
function host.validate(self, value, section)
   return luci.sys.call("nslookup " .. value) == 0 and value
end
]])
      assert_true(find(report, "709") ~= nil, "expected a 709")
   end)

   it("reports a CBI write callback's value reaching a command as 709", function()
      local report = scan("model/cbi", [[
function host.write(self, section, value)
   os.execute("echo " .. value)
end
]])
      assert_true(find(report, "709") ~= nil, "expected a 709")
   end)

   it("reports a controller's forwarded ... reaching a command through a helper as 709", function()
      local report = scan("controller", [[
local function run(cmdid, args)
   return args
end
function action_run(callback, ...)
   os.execute(run(...))
end
]])
      assert_true(find(report, "709") ~= nil, "expected a 709")
   end)

   it("keeps a shell-quoted formvalue a quoted 709, not a plain one", function()
      local report = scan("model/cbi", [[
local ip = s:option(Value, "ip")
function ip.parse(self, section)
   luci.sys.call("ping " .. luci.util.shellquote(ip:formvalue(section)))
end
]])
      local finding = find(report, "709")
      assert_true(finding == nil or finding.sanitizer == "shell-quoted", "a quoted value is not a bare 709")
   end)

   it("does not report a formvalue that never reaches a sink", function()
      local report = scan("model/cbi", [[
local ip = s:option(Value, "ip")
function ip.parse(self, section)
   local v = ip:formvalue(section)
   luci.sys.call("ping -c1 127.0.0.1")
   return v
end
]])
      assert_true(find(report, "709") == nil, "a constant command is not a 709")
   end)

   it("does not treat validate's value as request data outside a CBI model", function()
      local report = scan("util", [[
function host.validate(self, value, section)
   return luci.sys.call("nslookup " .. value) == 0
end
]])
      assert_true(find(report, "709") == nil, "only a model/cbi file is a CBI callback")
   end)
end)
