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

describe("large files", function()
   it("analyzes a file within the node budget with flow-sensitive dataflow", function()
      local report = api.check_source([[
local function go(host)
   local target = http.formvalue("host")
   os.execute("ping " .. target)
end
]])
      assert_equal(codes(report), "709")
   end)

   it("still finds the injection in a file too large for flow-sensitive analysis", function()
      local parts = {"local function go(host)"}
      for index = 1, 20000 do
         parts[#parts + 1] = ("   local filler%d = tostring(%d)"):format(index, index)
      end
      parts[#parts + 1] = '   os.execute("ping " .. http.formvalue("host"))'
      parts[#parts + 1] = "end"

      local report = api.check_source(table.concat(parts, "\n"), {max_nodes = 500})
      local found = {}
      for _, finding in ipairs(report) do found[#found + 1] = finding.code end
      table.sort(found)
      assert_equal(table.concat(found, ","), "709,904",
         "a large file is still checked, and says its analysis is approximate")
   end)

   it("completes on a large file in time proportional to its size", function()
      local parts = {}
      for index = 1, 4000 do parts[#parts + 1] = ("local v%d = tostring(%d)"):format(index, index) end
      local source = table.concat(parts, "\n")
      local started = os.clock()
      api.check_source(source, {max_nodes = 500})
      local elapsed = os.clock() - started
      assert_true(elapsed < 5,
         ("4000 statements took %.1fs, which is not proportional to input"):format(elapsed))
   end)
end)

describe("shell sanitizers and metacharacters", function()
   local function code_list(report)
      local out = {}
      for _, finding in ipairs(report) do out[#out + 1] = finding.code end
      table.sort(out)
      return table.concat(out, ",")
   end

   it("reports one 709 and no 712 when the tainted part is shell-quoted", function()
      local report = api.check_source([[
local function go(host)
   os.execute("ping " .. luci.util.shellquote(http.formvalue("host")))
end
]], {std = "luci"})
      assert_equal(code_list(report), "709",
         "quoting removes the injection but not the data flow")
      assert_equal(report[1].sanitizer, "shell-quoted",
         "the finding should say the data crossed a quoting helper")
   end)

   it("reports one 709 for a wholly unquoted command, not a duplicate 712", function()
      local report = api.check_source([[
local function go(host)
   os.execute("ping -c1 " .. http.formvalue("host"))
end
]])
      assert_equal(code_list(report), "709",
         "an unquoted request parameter is already the critical finding")
   end)

   it("reports 712 and names the metacharacters when quoting was attempted but missed", function()
      local report = api.check_source([[
local function go(prefix, rest)
   os.execute(luci.util.shellquote(http.formvalue("prefix")) .. " " .. http.formvalue("rest"))
end
]], {std = "luci"})
      assert_equal(code_list(report), "709,712",
         "quoting one request parameter and not the other is the mistake worth naming")
      local metachar = nil
      for _, finding in ipairs(report) do
         if finding.code == "712" then metachar = finding end
      end
      assert_true(metachar ~= nil, "expected a 712")
      assert_true(type(metachar.metachars) == "string" and #metachar.metachars > 0,
         "the 712 must name the characters that break out")
      assert_match(metachar.metachars, ";", "a semicolon is the classic breakout")
   end)

   it("never reports 712 for a dynamic code sink", function()
      local report = api.check_source([[
local function go(body)
   loadstring("return " .. http.formvalue("body"))
end
]])
      for _, finding in ipairs(report) do
         assert_true(finding.code ~= "712", "shell metacharacters are meaningless for loadstring")
      end
   end)

   it("recognizes a shell quoting helper defined in the same file", function()
      local report = api.check_source([[
local function shq(value)
   return "'" .. tostring(value):gsub("'", "'\\\\''") .. "'"
end
local function go(host)
   os.execute("ping " .. shq(http.formvalue("host")))
end
]])
      local found = {}
      for _, finding in ipairs(report) do found[#found + 1] = finding.code end
      assert_true(not table.concat(found, ","):find("712", 1, true),
         "a local quoting helper neutralizes the shell sink: " .. table.concat(found, ","))
   end)

   it("does not let a shell quoting helper silence a dynamic code sink", function()
      local report = api.check_source([[
local function go(body)
   loadstring(luci.util.shellquote(http.formvalue("body")))
end
]], {std = "luci"})
      local found = {}
      for _, finding in ipairs(report) do found[#found + 1] = finding.code end
      assert_true(table.concat(found, ","):find("710", 1, true),
         "quoting a string for a shell does nothing for loadstring: " .. table.concat(found, ","))
   end)
end)
