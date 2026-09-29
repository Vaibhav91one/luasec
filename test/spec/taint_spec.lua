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
      assert_equal(codes(report), "708",
         "an untraceable argument in an exported function is an exposure, not silence")
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

describe("taint across function boundaries", function()
   it("reports a request parameter that reaches os.execute through a wrapper", function()
      local report = api.check_source([[
local function run(cmd)
   os.execute(cmd)
end
local function go()
   run("ping " .. http.formvalue("host"))
end
]])
      local found = {}
      for _, finding in ipairs(report) do found[#found + 1] = finding.code end
      assert_equal(table.concat(found, ","), "709",
         "the sink is in run(), the source is in go(), and that is the bug")
   end)

   it("names the source line in the trace of a cross-function finding", function()
      local report = api.check_source([[
local function run(cmd)
   os.execute(cmd)
end
local function go()
   run("ping " .. http.formvalue("host"))
end
]])
      local finding = report[1]
      assert_true(finding.trace ~= nil, "a cross-function finding must carry a trace")
      local source_line
      for _, step in ipairs(finding.trace) do
         if step.kind == "source" then source_line = step.line end
      end
      assert_equal(source_line, 5, "the source is on the line that reads the request parameter")
   end)

   it("follows a two-level chain of wrappers", function()
      local report = api.check_source([[
local function inner(cmd)
   os.execute(cmd)
end
local function outer(cmd)
   inner(cmd)
end
outer(http.formvalue("host"))
]])
      local found = {}
      for _, finding in ipairs(report) do found[#found + 1] = finding.code end
      assert_equal(table.concat(found, ","), "709")
   end)

   it("stays silent when the wrapper is only ever called with a constant", function()
      local report = api.check_source([[
local function run(cmd)
   os.execute(cmd)
end
run("ping -c1 127.0.0.1")
]])
      for _, finding in ipairs(report) do
         assert_true(finding.code ~= "709",
            "a wrapper called only with a constant carries no untrusted data")
      end
   end)

   it("terminates on mutually recursive wrappers", function()
      local started = os.clock()
      local report = api.check_source([[
local function a(cmd)
   if cmd then b(cmd) else os.execute(cmd) end
end
local function b(cmd)
   a(cmd)
end
a(http.formvalue("host"))
]])
      local elapsed = os.clock() - started
      assert_true(elapsed < 3, ("mutual recursion took %.1fs"):format(elapsed))
      assert_true(#report > 0, "the injection is still found")
   end)

   it("reports a sink reached only through a wrapper as 708, not 709", function()
      local report = api.check_source([[
local function run(cmd)
   os.execute(cmd)
end
return run
]])
      local by_code = {}
      for _, finding in ipairs(report) do by_code[finding.code] = finding end
      assert_true(by_code["708"] ~= nil, "an exposed wrapper with no visible source is 708")
      assert_true(by_code["709"] == nil, "without a source the claim is exposure, not injection")
      assert_equal(by_code["708"].severity, "high",
         "708 carries the severity of the sink it wraps, because it replaces 701 there")
   end)

   it("follows a tainted argument passed through a local id function (A)", function()
      local report = api.check_source([[
local function id(x) return x end
local v = id(http.formvalue("h"))
os.execute(v)
]])
      local found = {}
      for _, finding in ipairs(report) do found[#found + 1] = finding.code end
      assert_true(table.concat(found, ","):find("709", 1, true),
         "a passing id helper must not hide the flow: " .. table.concat(found, ","))
      assert_true(table.concat(found, ","):find("708", 1, true) == nil,
         "no exposure when the source is visible through the return: " .. table.concat(found, ","))
   end)

   it("follows a tainted argument passed through a local id function inline (B)", function()
      local report = api.check_source([[
local function id(x) return x end
os.execute(id(http.formvalue("h")))
]])
      local found = {}
      for _, finding in ipairs(report) do found[#found + 1] = finding.code end
      assert_true(table.concat(found, ","):find("709", 1, true),
         "an inline call through id must not hide the flow: " .. table.concat(found, ","))
      assert_true(table.concat(found, ","):find("708", 1, true) == nil,
         "no exposure when the source is visible through the return: " .. table.concat(found, ","))
   end)

   it("follows a tainted source returned from a local function (C)", function()
      local report = api.check_source([[
local function get() return http.formvalue("h") end
os.execute(get())
]])
      local found = {}
      for _, finding in ipairs(report) do found[#found + 1] = finding.code end
      assert_true(table.concat(found, ","):find("709", 1, true),
         "a local function returning a source must not hide the flow: " .. table.concat(found, ","))
      assert_true(table.concat(found, ","):find("708", 1, true) == nil,
         "no exposure when the source is visible through the return: " .. table.concat(found, ","))
   end)

   it("stays silent when a local id function is only ever called with a constant", function()
      local report = api.check_source([[
local function id(x) return x end
os.execute(id("ls"))
]])
      for _, finding in ipairs(report) do
         assert_true(finding.code ~= "709",
            "a constant argument through id must not produce 709: " .. finding.code)
      end
   end)

   it("terminates on a directly recursive id function fed a source", function()
      local started = os.clock()
      api.check_source([[
local function r(x)
   if x then return r(x) end
   return x
end
os.execute(r(http.formvalue("h")))
]])
      local elapsed = os.clock() - started
      assert_true(elapsed < 3, ("recursion took %.1fs"):format(elapsed))
   end)

   it("terminates on a fan-out chain of id functions under 3 s", function()
      local started = os.clock()
      local lines = {"local function f0(x) return x end"}
      for i = 1, 12 do
         lines[#lines + 1] = ("local function f%d(x) return f%d(x) .. f%d(x) .. f%d(x) .. f%d(x) end"):format(i, i - 1, i - 1, i - 1, i - 1)
      end
      lines[#lines + 1] = 'os.execute(f12(http.formvalue("h")))'
      local report = api.check_source(table.concat(lines, "\n"))
      local elapsed = os.clock() - started
      assert_true(elapsed < 3, ("fan-out chain took %.1fs, not linear"):format(elapsed))
      local found = {}
      for _, finding in ipairs(report) do found[#found + 1] = finding.code end
      assert_true(table.concat(found, ","):find("709", 1, true),
         "the fan-out chain must still report 709: " .. table.concat(found, ","))
   end)

    it("follows a tainted value out of a local function bound to a module field", function()
       local report = api.check_source([[
       local M = {}
       function M.id(x) return x end
       os.execute(M.id(http.formvalue("h")))
       ]])
       local found = {}
       for _, finding in ipairs(report) do found[#found + 1] = finding.code end
       assert_true(table.concat(found, ","):find("709", 1, true),
          "a module field returning its argument must not hide the flow: " .. table.concat(found, ","))
       assert_true(table.concat(found, ","):find("708", 1, true) == nil,
          "no exposure when the source is visible through the module field: " .. table.concat(found, ","))
    end)

    it("follows a tainted value out of a module field assigned with an anonymous function", function()
       local report = api.check_source([[
       local M = {}
       M.id = function(x) return x end
       os.execute(M.id(http.formvalue("h")))
       ]])
       local found = {}
       for _, finding in ipairs(report) do found[#found + 1] = finding.code end
       assert_true(table.concat(found, ","):find("709", 1, true),
          "M.id = function(x) return x end must not hide the flow: " .. table.concat(found, ","))
    end)

    it("recognizes a shell quoting helper defined as a module field", function()
       local report = api.check_source([[
       local M = {}
        function M.q(s) return "'" .. tostring(s):gsub("'", "'\\\\''") .. "'" end
       os.execute("echo " .. M.q(http.formvalue("h")))
       ]])
       local found = {}
       for _, finding in ipairs(report) do found[#found + 1] = finding.code end
       assert_true(not table.concat(found, ","):find("712", 1, true),
          "a quoting field helper neutralizes the shell sink: " .. table.concat(found, ","))
       assert_equal(report[1].sanitizer, "shell-quoted",
          "the finding should say the data crossed a quoting helper")
    end)

    it("follows only the shadowed local M whose field returns its argument", function()
       local report = api.check_source([[
       local M = {}
       function M.id(x) return "safe" end
       os.execute(M.id(http.formvalue("h")))
       local M = {}
       function M.id(x) return x end
       os.execute(M.id(http.formvalue("h")))
       ]])
       local found = {}
       for _, finding in ipairs(report) do found[#found + 1] = finding.code end
       assert_true(table.concat(found, ","):find("709", 1, true),
          "only the call through the x-returning shadow reports 709: " .. table.concat(found, ","))
       -- The "safe"-returning shadow must not produce its own 709.
       local count = 0
       for _, code in ipairs(found) do if code == "709" then count = count + 1 end end
       assert_equal(count, 1, "exactly one 709 from the x-returning shadow: " .. table.concat(found, ","))
    end)
end)

describe("sources beyond HTTP", function()
   it("treats a file read as untrusted data", function()
      local report = api.check_source([[
local function go(path)
   local handle = io.open(path, "r")
   local body = handle:read("*a")
   os.execute("echo " .. body)
end
]])
      assert_equal(codes(report), "709", "a file's contents reach a shell")
   end)

   it("treats decoded JSON as untrusted data", function()
      local report = api.check_source([[
local json = require "luci.jsonc"
local function go(body)
   local parsed = json.parse(body)
   os.execute("echo " .. parsed.cmd)
end
]], {std = "openwrt+luci"})
      assert_equal(codes(report), "709", "a decoded field reaches a shell")
   end)

   it("tracks a variable the operator declared as a source", function()
      local report = api.check_source([[
local function go(inbound)
   os.execute("echo " .. inbound)
end
]], {sources = {"inbound"}})
      assert_equal(codes(report), "709",
         "an operator can declare a name that carries untrusted data")
   end)

   it("keeps the declared source at a lower confidence than a request parameter", function()
      local report = api.check_source([[
local function go(inbound)
   os.execute("echo " .. inbound)
end
]], {sources = {"inbound"}, source_confidence = "medium"})
      assert_equal(report[1].confidence, "medium")
   end)

   it("does not treat a value from a local helper as untrusted by itself", function()
      local report = api.check_source([[
local function quote(value)
   return "'" .. tostring(value) .. "'"
end
local function go(inbound)
   os.execute("echo " .. quote(inbound))
end
]])
      for _, finding in ipairs(report) do
         assert_true(finding.code ~= "709",
            "a quoting helper does not make data untrusted: " .. finding.code)
      end
   end)
end)
