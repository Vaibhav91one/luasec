local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_match = harness.assert_equal, harness.assert_match

local api = require "luadoctor.api"

-- `nixio.exec` is overloaded. The registry used to declare a single command
-- position -- the first -- which covers `nixio.exec(command)` and is wrong for
-- `nixio.exec("/bin/sh", "-c", command)`, the form OpenWrt code actually uses
-- to reach a shell. Both positions are declared now, and these specs say which
-- flows report and which must stay silent.

local function with_code(report, code)
   local out = {}
   for _, finding in ipairs(report) do
      if finding.code == code then out[#out + 1] = finding end
   end
   return out
end

local function fixture(name, opts)
   local handle = assert(io.open("test/fixtures/firmware/" .. name, "r"))
   local source = handle:read("*a")
   handle:close()
   return api.check_source(source, opts)
end

describe("nixio.exec: the shell form is a sink", function()
   it("reports a request parameter reaching nixio.exec as the third argument", function()
      local report = fixture("nixio_exec_shell_form.lua", {std = "+openwrt"})
      local found = with_code(report, "709")
      assert_equal(#found, 1,
         "a request parameter handed to /bin/sh is untrusted data reaching command execution")
      assert_equal(found[1].name, "nixio.exec")
   end)

   it("reports the shell form from the CLI, not only through the API", function()
      local out, code = harness.cli({"--std", "+openwrt",
         "test/fixtures/firmware/nixio_exec_shell_form.lua"})
      assert_equal(code, 1, "a critical finding makes the run exit non-zero")
      assert_match(out, "%[709%] critical")
   end)

   it("reports the shell form under the openwrt profile alone", function()
      local report = api.check_source([[
nixio.exec("/bin/sh", "-c", uci.get("system", "hostname"))
]], {std = "openwrt", report_dynamic_sinks = false})
      assert_equal(#with_code(report, "709"), 1,
         "the shell form is a sink wherever the openwrt profile is loaded")
   end)
end)

describe("nixio.exec: the direct form stays a sink", function()
   it("still reports a request parameter as the first argument", function()
      local report = fixture("nixio_exec_direct_form.lua", {std = "+openwrt"})
      local found = with_code(report, "709")
      assert_equal(#found, 1, "nixio.exec(command) was reporting before and must keep reporting")
      assert_equal(found[1].name, "nixio.exec")
   end)

   it("still reports a computed first argument with no known taint", function()
      local report = api.check_source([[
local name = mylib.getname()
nixio.exec(name)
]], {std = "openwrt"})
      assert_equal(#with_code(report, "701"), 1,
         "a command we cannot prove constant is still an execution sink")
   end)
end)

-- `nixio.exec` is one of three functions in nixio's process module, and the
-- other two were not declared at all. All three take the command FIRST --
-- process.c:31 reads `luaL_checkstring(L, 1)` as the path and passes it to
-- execv, execvp or execve depending on which of the three was called -- so a
-- declaration written for one of them is the declaration for the other two.
--
-- They matter separately because a firmware file calls one of them and the
-- others are not there: execp is the PATH search and exece is the one that
-- takes an argv and an environment table, and neither has the third-argument
-- shell form `nixio.exec` has.
describe("nixio.execp and nixio.exece are the other two process functions", function()
   it("reports a request parameter reaching nixio.execp", function()
      local report = fixture("nixio_execp_form.lua", {std = "+openwrt"})
      local found = with_code(report, "709")
      assert_equal(#found, 1,
         "nixio.execp(tainted) is command execution and reported nothing at all")
      assert_equal(found[1].name, "nixio.execp")
   end)

   it("reports a request parameter reaching nixio.exece as the command", function()
      local report = fixture("nixio_exece_form.lua", {std = "+openwrt"})
      local found = with_code(report, "709")
      assert_equal(#found, 1,
         "nixio.exece takes the command first and the argv table second, so " ..
         "position 1 is the command; reported nothing at all")
      assert_equal(found[1].name, "nixio.exece")
   end)

   it("reports both from the CLI, not only through the API", function()
      for _, name in ipairs({"nixio_execp_form.lua", "nixio_exece_form.lua"}) do
         local out, code = harness.cli({"--std", "+openwrt",
            "test/fixtures/firmware/" .. name})
         assert_equal(code, 1, name .. ": a critical finding makes the run exit non-zero")
         assert_match(out, "%[709%] critical")
      end
   end)

   it("still reports a computed command it cannot prove is fixed", function()
      -- The same shape as the `nixio.exec` spec above, and for the same
      -- reason: 701 is the "this call is an execution sink" answer and it does
      -- not need a source to say so.
      for _, call in ipairs({
         "nixio.execp(mylib.getname())",
         'nixio.exece(mylib.getname(), {})',
      }) do
         local report = api.check_source(call, {std = "openwrt"})
         assert_equal(#with_code(report, "701"), 1,
            call .. ": a command we cannot prove constant is still an execution sink")
      end
   end)

   it("leaves a fixed command and a fixed argv silent in both", function()
      local report = api.check_source([[
nixio.execp("/usr/bin/uptime")
nixio.exece("/bin/true", {"true"})
]], {std = "openwrt"})
      assert_equal(#report, 0,
         "declaring the other two forms must not turn every nixio.exec* call into a finding")
   end)
end)

describe("nixio.exec: a fixed command stays silent in both forms", function()
   it("leaves a fixed shell command silent", function()
      local report = api.check_source([[
nixio.exec("/bin/sh", "-c", "uptime")
]], {std = "openwrt"})
      assert_equal(#report, 0, "a literal command has nothing untrusted in it")
   end)

   it("leaves a direct call with a literal command and literal options silent", function()
      local report = api.check_source([[
nixio.exec("/bin/ls", "-l", "/tmp")
]], {std = "openwrt"})
      assert_equal(#report, 0,
         "the shell form's position only adds a report where the command is not fixed")
   end)

   it("leaves a two-argument direct call silent when both are fixed", function()
      local report = api.check_source([[
nixio.exec("/bin/ls", "-l")
]], {std = "openwrt"})
      assert_equal(#report, 0)
   end)
end)
