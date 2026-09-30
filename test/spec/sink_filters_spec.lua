local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true, assert_match = harness.assert_equal, harness.assert_true, harness.assert_match

local api = require "luasec.api"
local profiles = require "luasec.registry.profiles"

local function at(report, code)
   for _, finding in ipairs(report) do
      if finding.code == code then return finding end
   end
end

local function write_tmp(content)
   local path = os.tmpname()
   local fh = assert(io.open(path, "w"))
   fh:write(content)
   fh:close()
   return path
end

describe("sink filters", function()
   it("names survivors and lowers confidence one step on a filtered position", function()
      local filtered = api.check_source([[
util.runShellCmd("ls " .. cgi["d"])
]], {std = "cgilua"})
      local plain = api.check_source([[
os.execute("ls " .. cgi["d"])
]], {std = "cgilua"})
      local f = at(filtered, "709")
      local p = at(plain, "709")
      assert_true(f ~= nil, "filtered sink still reports")
      assert_true(p ~= nil, "plain sink reports")
      assert_equal(f.code, p.code)
      assert_match(f.message, "partial filter")
      assert_equal(f.confidence, "high")
      assert_equal(p.confidence, "certain")
   end)

   it("reports a tainted options argument at full confidence with no note", function()
      local report = api.check_source([[
util.runShellCmd("ls", "out", "err", cgi["opt"])
]], {std = "cgilua"})
      local f = at(report, "709")
      assert_true(f ~= nil, "options position is reported")
      assert_equal(f.confidence, "certain")
      assert_true(not f.message:find("partial filter", 1, true), "no filter note, got " .. f.message)
   end)

   it("filters position 1 but not position 2 of shellCmdOutput", function()
      local first = api.check_source([[
util.shellCmdOutput("ls " .. cgi["d"])
]], {std = "cgilua"})
      local f1 = at(first, "709")
      assert_true(f1 ~= nil, "position 1 reports")
      assert_match(f1.message, "partial filter")
      assert_equal(f1.confidence, "high")
      local second = api.check_source([[
util.shellCmdOutput("ls", cgi["opt"])
]], {std = "cgilua"})
      local f2 = at(second, "709")
      assert_true(f2 ~= nil, "position 2 reports")
      assert_equal(f2.confidence, "certain")
      assert_true(not f2.message:find("partial filter", 1, true), "no filter note, got " .. f2.message)
   end)

   it("leaves a sink with no filters byte-identical", function()
      local report = api.check_source([[
os.execute("ls " .. cgi["d"])
]], {std = "cgilua"})
      local f = at(report, "709")
      assert_true(f ~= nil, "os.execute reports")
      assert_equal(f.message, "untrusted data reaches command execution (os.execute)")
      assert_equal(f.confidence, "certain")
   end)

   it("rejects a filters field that is not a table of position to string", function()
      local bad1 = write_tmp([[return {name = "x", sinks = {{pattern = "a.b", code = "701", kind = "exec", arg = {1}, filters = "x"}}}]])
      local dec1, err1 = profiles.load_file(bad1)
      assert_true(dec1 == nil, "filters as string must be rejected")
      assert_match(tostring(err1), "filters")
      local bad2 = write_tmp([[return {name = "x", sinks = {{pattern = "a.b", code = "701", kind = "exec", arg = {1}, filters = {x = "abc"}}}}]])
      local dec2, err2 = profiles.load_file(bad2)
      assert_true(dec2 == nil, "non-number filters key must be rejected")
      assert_match(tostring(err2), "filters")
   end)

   it("honours filters from a custom rules profile", function()
      local path = write_tmp([[return {name = "x", sinks = {{pattern = "myexec.run", code = "701", kind = "exec", arg = {1}, filters = {[1] = ";`$&|<>"}}}}]])
      local report = api.check_source([[
myexec.run("ls " .. http.formvalue("h"))
]], {rules = {path}})
      local f = at(report, "709")
      assert_true(f ~= nil, "custom filtered sink reports")
      assert_match(f.message, "partial filter")
      assert_equal(f.confidence, "high")
   end)
end)
