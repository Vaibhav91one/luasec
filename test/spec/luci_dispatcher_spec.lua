-- The LuCI dispatcher: a controller module's exported functions are called by
-- luci.dispatcher with the URL's node name and path segments as arguments. The
-- luci profile declares those arguments as request data, so a sink fed one is a
-- 709 rather than a 708 "nothing in this file feeds it".
local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true, assert_match = harness.assert_equal, harness.assert_true, harness.assert_match

local api = require "luasec.api"

--- Write a file under a fresh `root/usr/lib/lua/luci/` tree and return its path.
--- The subdirectory is part of the behaviour under test, not decoration: only
--- what lives under `controller/` is a dispatcher module.
local function luci_file(tag, subdir, name, body)
   local dir = harness.scratch_dir(tag) .. "/root/usr/lib/lua/luci/" .. subdir
   os.execute(("mkdir -p %q"):format(dir))
   local path = dir .. "/" .. name
   local handle = assert(io.open(path, "w"))
   handle:write(body)
   handle:close()
   return path
end

local function controller(tag, name, body)
   return luci_file(tag, "controller", name, body)
end

local function codes(report)
   local out = {}
   for _, finding in ipairs(report) do out[#out + 1] = finding.code end
   table.sort(out)
   return table.concat(out, ",")
end

local function of(report, code)
   for _, finding in ipairs(report) do
      if finding.code == code then return finding end
   end
end

describe("luci dispatcher", function()
   it("reports a dispatcher handler's argument reaching a command-execution sink", function()
      local path = controller("luci_dispatcher", "lxc.lua", [[
function lxc_create(lxc_name, lxc_template)
   luci.sys.call("/usr/bin/lxc-create --name " .. lxc_name)
end
]])
      local report = api.analyze({path}, {std = "luci"})
      assert_true(of(report, "709") ~= nil, "expected a 709, got " .. codes(report))
   end)

   it("treats every URL segment a handler receives as request data, not only the first", function()
      local path = controller("luci_dispatcher", "ddns.lua", [[
function act_update(host, domain)
   luci.sys.call("/usr/sbin/ddns-update " .. domain)
end
]])
      local report = api.analyze({path}, {std = "luci"})
      assert_true(of(report, "709") ~= nil, "the second URL segment is request data too, got " .. codes(report))
   end)

   it("treats a handler's vararg as request data", function()
      local path = controller("luci_dispatcher", "splash.lua", [[
M.apply = function(...)
   luci.sys.call("/usr/sbin/splash-lease " .. (...))
end
]])
      local report = api.analyze({path}, {std = "luci"})
      assert_true(of(report, "709") ~= nil, "expected a 709, got " .. codes(report))
   end)

   it("leaves the same handler shape outside the dispatcher directory alone", function()
      local path = luci_file("luci_dispatcher", "model/cbi", "lxc.lua", [[
function write(name)
   luci.sys.call("/usr/bin/lxc-create --name " .. name)
end
]])
      local report = api.analyze({path}, {std = "luci"})
      assert_true(of(report, "709") == nil, "a cbi widget is not a dispatcher module, got " .. codes(report))
   end)

   it("reports a vararg collected into a table and concatenated back into a command", function()
      -- The shape luci-app-commands uses: `call("action_run")` hands the URL path
      -- over as `...`, and the handler rebuilds it as an argv table and runs it.
      local path = controller("luci_dispatcher", "commands.lua", [[
function action_run(...)
   local argv = {...}
   os.execute(table.concat(argv, " "))
end
]])
      local report = api.analyze({path}, {std = "luci"})
      local finding = of(report, "709")
      assert_true(finding ~= nil, "expected a 709, got " .. codes(report))
      assert_match(finding.source, "vararg", "the source names the vararg, not a parameter")
   end)
end)

describe("luci request sources", function()
   it("treats luci.http.getenv as request data", function()
      local report = api.check_source([[
local remote = luci.http.getenv("HTTP_X_FORWARDED_FOR")
luci.sys.call("/usr/sbin/splash-block " .. remote)
]], {std = "luci"})
      assert_equal(codes(report), "709")
      assert_equal(of(report, "709").source, "luci.http.getenv")
   end)

   it("leaves luci.http.getenv silent when the tool is not given the luci profile", function()
      local report = api.check_source([[
local remote = luci.http.getenv("HTTP_X_FORWARDED_FOR")
luci.sys.call("/usr/sbin/splash-block " .. remote)
]])
      assert_true(not codes(report):match("709"), "no 709 without the std, got " .. codes(report))
   end)
end)