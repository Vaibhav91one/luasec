local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true = harness.assert_equal, harness.assert_true

local api = require "luasec.api"

local function codes(report)
   local out = {}
   for _, finding in ipairs(report) do out[#out + 1] = finding.code end
   table.sort(out)
   return table.concat(out, ",")
end

describe("taint analysis: command execution", function()
   it("reports an HTTP parameter concatenated into os.execute as 709 critical", function()
      local report = api.check_source([[
local function status(host)
   os.execute("ping -c1 " .. http.formvalue(host))
end
]])
      assert_equal(codes(report), "709", "expected exactly one 709 finding")
      local finding = report[1]
      assert_equal(finding.severity, "critical")
      assert_equal(finding.name, "os.execute")
      assert_equal(finding.line, 2, "the os.execute call is on the second line of the fixture")
   end)
end)

describe("taint analysis: propagation through the shapes firmware code uses", function()
   it("follows a tainted value through a local", function()
      local report = api.check_source([[
local function run(host)
   local target = http.formvalue("host")
   os.execute("ping " .. target)
end
]])
      assert_equal(codes(report), "709")
   end)

   it("follows a tainted value into a table field", function()
      local report = api.check_source([[
local M = {}
function M.go(host)
   M.cmd = http.formvalue("host")
   os.execute(M.cmd)
end
return M
]])
      assert_equal(codes(report), "709")
   end)

   it("follows a tainted value out of a table constructor", function()
      local report = api.check_source([[
local function go(host)
   local t = {cmd = http.formvalue("host")}
   os.execute(t.cmd)
end
]])
      assert_equal(codes(report), "709")
   end)

   it("follows a tainted value through tostring", function()
      local report = api.check_source([[
local function go(host)
   local target = tostring(http.formvalue("host"))
   os.execute("ping " .. target)
end
]])
      assert_equal(codes(report), "709")
   end)

   it("follows a tainted value through string.gsub", function()
      local report = api.check_source([[
local function go(host)
   local target = string.gsub(http.formvalue("host"), " ", "")
   os.execute("ping " .. target)
end
]])
      assert_equal(codes(report), "709")
   end)

   it("reports the same findings when the variables are renamed", function()
      local function analyze(host_name)
         return api.check_source(([[
local function go(host_name)
   local target = http.formvalue(host_name)
   os.execute("ping " .. target)
end
]]):format(host_name))
      end
      local first = analyze("host")
      local second = analyze("target")
      assert_equal(#first, #second)
      assert_equal(first[1].line, second[1].line)
      assert_equal(first[1].code, second[1].code)
   end)

   it("stays silent when every part of the command is constant", function()
      local report = api.check_source([[
local function go()
   os.execute("ping -c1 " .. "127.0.0.1")
end
]])
      assert_equal(codes(report), "", "a folded constant must not look like a sink")
   end)

   it("still reports a command built from a value the analyzer cannot fold", function()
      local report = api.check_source([[
local function go(host)
   os.execute("ping " .. host)
end
]])
      assert_equal(codes(report), "701", "an unprovable argument is a 701, not a silent pass")
   end)
end)
