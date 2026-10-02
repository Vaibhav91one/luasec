-- Entry points: functions a profile declares as called with request data.
-- Their named arguments are tainted at entry, so a flow to a sink inside them
-- is a proven 709 instead of the 708 "nothing in this file feeds it".
local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true, assert_match = harness.assert_equal, harness.assert_true, harness.assert_match

local api = require "luasec.api"
local profiles = require "luasec.registry.profiles"

local function write_tmp(content)
   local path = os.tmpname()
   local handle = assert(io.open(path, "w"))
   handle:write(content)
   handle:close()
   return path
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

local HANDLER = [[
function handle_set(req, extra)
   os.execute("run " .. req.name)
end
]]

describe("entry points", function()
   it("taints the declared argument so the sink is a 709, not a 708", function()
      local path = write_tmp([[return {name = "x", entry_points = {{pattern = "handle_*", arg = {1}}}}]])
      local report = api.check_source(HANDLER, {rules = {path}})
      assert_true(of(report, "709") ~= nil, "expected a 709, got " .. codes(report))
      assert_true(of(report, "708") == nil, "the 708 at that site is dropped, got " .. codes(report))
      assert_match(of(report, "709").source, "entry", "the source names the entry point")
   end)

   it("without the declaration the same function is only a 708", function()
      local report = api.check_source(HANDLER, {})
      assert_true(of(report, "709") == nil, "no 709 without an entry point, got " .. codes(report))
      assert_true(of(report, "708") ~= nil, "the 708 stays, got " .. codes(report))
   end)

   it("taints only the declared argument positions", function()
      local path = write_tmp([[return {name = "x", entry_points = {{pattern = "handle_*", arg = {2}}}}]])
      local report = api.check_source(HANDLER, {rules = {path}})
      assert_true(of(report, "709") == nil, "argument 1 is not declared, got " .. codes(report))
   end)

   it("leaves a function whose name does not match alone", function()
      local path = write_tmp([[return {name = "x", entry_points = {{pattern = "serve_*", arg = {1}}}}]])
      local report = api.check_source(HANDLER, {rules = {path}})
      assert_true(of(report, "709") == nil, "no match, no taint, got " .. codes(report))
   end)

   it("matches the short name of a dotted function", function()
      local path = write_tmp([[return {name = "x", entry_points = {{pattern = "on_*", arg = {1}}}}]])
      local report = api.check_source("local M = {}\nfunction M.on_request(req) os.execute('x ' .. req.cmd) end\nreturn M\n", {rules = {path}})
      assert_true(of(report, "709") ~= nil, "expected a 709, got " .. codes(report))
   end)

   it("the cgilua std declares the mesh handlers", function()
      local src = "function loginHandler(methodObj, meshRequestMethod)\n   os.execute(\"x \" .. methodObj.user)\nend\n"
      local report = api.check_source(src, {std = "cgilua"})
      assert_true(of(report, "709") ~= nil, "expected a 709 under cgilua, got " .. codes(report))
      local plain = api.check_source(src, {})
      assert_true(of(plain, "709") == nil, "and none without it, got " .. codes(plain))
   end)

   it("does not leak an entry point into a later run", function()
      local path = write_tmp([[return {name = "x", entry_points = {{pattern = "handle_*", arg = {1}}}}]])
      api.check_source(HANDLER, {rules = {path}})
      local later = api.check_source(HANDLER, {})
      assert_true(of(later, "709") == nil, "the declaration must not survive its run, got " .. codes(later))
   end)

   it("an entry with a file glob applies to functions in matching files only", function()
      local dir = harness.scratch_dir("entry_file")
      local mesh, other = dir .. "/lib/easyMeshSet.lua", dir .. "/lib/other.lua"
      os.execute(("mkdir -p %q"):format(dir .. "/lib"))
      local source = "function setThing(obj)\n   os.execute(\"x \" .. obj.name)\nend\n"
      for _, path in ipairs({mesh, other}) do
         local handle = assert(io.open(path, "w"))
         handle:write(source)
         handle:close()
      end
      local rules = write_tmp([[return {name = "x", entry_points = {{pattern = "*", file = "*/easyMesh*.lua", arg = {1}}}}]])
      local report = api.analyze({mesh, other}, {rules = {rules}})
      os.execute(("rm -rf %q"):format(dir))
      local by_file = {}
      for _, finding in ipairs(report) do
         if finding.code == "709" then by_file[finding.file] = true end
      end
      assert_true(by_file[mesh], "the matching file's handler is a 709, got " .. codes(report))
      assert_true(not by_file[other], "a file the glob does not match stays a 708, got " .. codes(report))
   end)

   it("a file-glob entry never matches source with no path", function()
      local path = write_tmp([[return {name = "x", entry_points = {{pattern = "handle_*", file = "*", arg = {1}}}}]])
      local report = api.check_source(HANDLER, {rules = {path}})
      assert_true(of(report, "709") == nil, "check_source has no file to match, got " .. codes(report))
   end)

   it("rejects a file glob that is not a string", function()
      local bad = write_tmp([[return {name = "x", entry_points = {{pattern = "a*", file = 3}}}]])
      local dec, err = profiles.load_file(bad)
      assert_true(dec == nil, "a non-string file must be rejected")
      assert_match(tostring(err), "file")
   end)

   it("rejects an entry point with no pattern or a non-numeric arg", function()
      local none = write_tmp([[return {name = "x", entry_points = {{arg = {1}}}}]])
      local dec, err = profiles.load_file(none)
      assert_true(dec == nil, "a missing pattern must be rejected")
      assert_match(tostring(err), "pattern")
      local bad = write_tmp([[return {name = "x", entry_points = {{pattern = "a*", arg = {"1"}}}}]])
      local dec2, err2 = profiles.load_file(bad)
      assert_true(dec2 == nil, "a string arg position must be rejected")
      assert_match(tostring(err2), "arg")
   end)
end)
