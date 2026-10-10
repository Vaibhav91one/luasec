-- A finding records which channel reaches the sink (web, acs, cli, ...), from a
-- channel tag on the source or entry-point declaration. The label is in the
-- plain message and in the `channels` field of the report contract.
local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true, assert_match = harness.assert_equal, harness.assert_true, harness.assert_match

local api = require "luadoctor.api"
local profiles = require "luadoctor.registry.profiles"

local function at(report, code)
   for _, finding in ipairs(report) do if finding.code == code then return finding end end
end

local function write_tmp(content)
   local path = os.tmpname()
   local handle = assert(io.open(path, "w"))
   handle:write(content); handle:close()
   return path
end

describe("channel labels", function()
   it("labels a web-sourced command execution as reachable from web", function()
      local report = api.check_source('os.execute("ls " .. cgi["d"])\n', {std = "cgilua"})
      local f = at(report, "709")
      assert_true(f ~= nil, "a 709 is reported")
      assert_match(f.message, "%[reachable from: web%]")
      assert_equal(f.channels[1], "web")
   end)

   it("has no channel field when no source declares one", function()
      local rules = write_tmp([[return {name = "x", sources = {{pattern = "input.read", id = "r", name = "r", confidence = "high"}}}]])
      local report = api.check_source('os.execute("x " .. input.read())\n', {rules = {rules}})
      local f = at(report, "709")
      assert_true(f ~= nil)
      assert_true(f.channels == nil, "an undeclared channel is not guessed")
      assert_no_match = assert_no_match or harness.assert_no_match
      assert_true(not f.message:find("reachable from", 1, true), "no channel note")
   end)

   it("a file-scoped entry point wins over a global one of the same name", function()
      local rules = write_tmp([[return {name = "x", entry_points = {
         {pattern = "*Handler", arg = {1}, channel = "web"},
         {pattern = "*Handler", file = "*/acslib/*.lua", arg = {1}, channel = "acs"},
      }}]])
      -- A handler in an acslib file resolves to the acs entry.
      local dir = harness.scratch_dir("channel_acs")
      os.execute(("mkdir -p %q"):format(dir .. "/acslib"))
      local p = dir .. "/acslib/h.lua"
      local handle = assert(io.open(p, "w"))
      handle:write("function pingHandler(req) os.execute('x ' .. req.host) end\n")
      handle:close()
      local report = api.analyze({p}, {rules = {rules}})
      os.execute(("rm -rf %q"):format(dir))
      local f = at(report, "709")
      assert_true(f ~= nil, "a 709 fires via the entry point")
      assert_equal(f.channels[1], "acs", "the file-scoped acs entry wins")
   end)

   it("rejects a non-string channel in a profile", function()
      local bad = write_tmp([[return {name = "x", sources = {{pattern = "a", channel = 3}}}]])
      local dec, err = profiles.load_file(bad)
      assert_true(dec == nil)
      assert_match(tostring(err), "channel")
   end)
end)
