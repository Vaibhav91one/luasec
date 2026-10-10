local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true = harness.assert_equal, harness.assert_true

local api = require "luadoctor.api"

-- How a sink is *reached* should not decide whether it is reported. A table of
-- handlers is an ordinary shape in firmware, not an evasion, so an alias plus a
-- table hop has to land on the same finding the direct call produces.
--
-- The other half is a limit, not a feature: a dispatch by a key the analyzer
-- cannot read at compile time stays silent. The tool must not guess which
-- function a runtime-chosen field names, because a wrong guess here is a false
-- positive on a program that never reached a sink.

local function findings_for(source, opts)
   return api.check_source(source, opts or {std = "luci"})
end

local function only(report)
   assert_equal(#report, 1,
      "expected exactly one finding, got: " .. #report)
   return report[1]
end

local function signature(finding)
   return table.concat({
      finding.code, finding.severity, finding.confidence, finding.cwe or "",
   }, " ")
end

describe("a sink reached through an alias", function()
   it("reports a sink aliased to a local and reached through a table field", function()
      local report = findings_for([[
local L = loadstring
local t = { run = L }
local p = luci.http.formvalue("q")
t.run(p)
]])
      local finding = only(report)
      assert_equal(finding.code, "710")
      assert_equal(finding.severity, "critical")
      assert_equal(finding.confidence, "certain")
      assert_equal(finding.name, "loadstring",
         "the finding names the function reached, not the field it hung on")
      assert_equal(finding.line, 4, "the call is on the fourth line")
   end)

   it("reports a table field holding the sink global directly", function()
      local report = findings_for([[
local t = { run = loadstring }
local p = luci.http.formvalue("q")
t.run(p)
]])
      local finding = only(report)
      assert_equal(finding.code, "710")
      assert_equal(finding.name, "loadstring")
   end)

   it("reports a sink reached through a field assigned after the table is made", function()
      local report = findings_for([[
local L = loadstring
local M = {}
M.run = L
local p = luci.http.formvalue("q")
M.run(p)
]])
      local finding = only(report)
      assert_equal(finding.code, "710")
      assert_equal(finding.name, "loadstring")
   end)

   it("reports a sink reached through a chain of table hops", function()
      local report = findings_for([[
local L = loadstring
local inner = { fn = L }
local outer = { run = inner.fn }
local p = luci.http.formvalue("q")
outer.run(p)
]])
      local finding = only(report)
      assert_equal(finding.code, "710")
      assert_equal(finding.name, "loadstring")
   end)

   it("reports every bare-global code sink reached through a table field", function()
      for _, sink in ipairs({"loadstring", "dofile", "load"}) do
         local report = findings_for(([[
local t = { run = %s }
local p = luci.http.formvalue("q")
t.run(p)
]]):format(sink))
         local finding = only(report)
         assert_equal(finding.code, "710", sink .. " reports as a dynamic-code sink")
         assert_equal(finding.name, sink)
      end
   end)

   it("reports an exec sink reached through a table field", function()
      local report = findings_for([[
local t = { run = os.execute }
local p = luci.http.formvalue("q")
t.run(p)
]])
      local finding = only(report)
      assert_equal(finding.code, "709")
      assert_equal(finding.severity, "critical")
      assert_equal(finding.name, "os.execute")
   end)

   it("reports the aliased call exactly as the direct call reports it", function()
      local direct = only(findings_for([[
local p = luci.http.formvalue("q")
loadstring(p)
]]))
      local aliased = only(findings_for([[
local L = loadstring
local t = { run = L }
local p = luci.http.formvalue("q")
t.run(p)
]]))
      assert_equal(signature(aliased), signature(direct),
         "an alias must not move the code, severity, confidence or CWE")
      assert_equal(aliased.message, direct.message,
         "the message names the same sink, so it must be the same string")
   end)

   it("does not change the finding set when the alias is renamed", function()
      local one = only(findings_for([[
local L = loadstring
local t = { run = L }
local p = luci.http.formvalue("q")
t.run(p)
]]))
      local two = only(findings_for([[
local Wombat = loadstring
local handlers = { run = Wombat }
local p = luci.http.formvalue("q")
handlers.run(p)
]]))
      assert_equal(signature(one), signature(two))
      assert_equal(one.message, two.message)
      assert_equal(one.line, two.line, "the call is on the same line of both fixtures")
   end)
end)

describe("a dispatch the analyzer cannot resolve stays silent", function()
   it("does not report a call through a key held in a variable", function()
      local report = findings_for([[
local L = loadstring
local t = { run = L }
local name = luci.http.formvalue("which")
local p = luci.http.formvalue("q")
t[name](p)
]])
      assert_equal(#report, 0,
         "a runtime-chosen key names no function the analyzer can see")
   end)

   it("does not report a call through a key that is only constant by assignment", function()
      -- `local name = "run"` is constant today and can be `"evil"` tomorrow;
      -- resolving the index from the first assignment is guessing.
      local report = findings_for([[
local t = { run = loadstring }
local name = "run"
local p = luci.http.formvalue("q")
t[name](p)
]])
      assert_equal(#report, 0, "a computed key is a computed key")
   end)

   it("does not report a field of a table it was never shown", function()
      local report = findings_for([[
local function dispatch(t, p)
   t.run(p)
end
dispatch({run = loadstring}, luci.http.formvalue("q"))
]])
      assert_equal(#report, 0, "the table's contents are unknown inside dispatch")
   end)

   it("does not report a field holding an anonymous function", function()
      local report = findings_for([[
local t = { run = function(code) return code end }
local p = luci.http.formvalue("q")
t.run(p)
]])
      assert_equal(#report, 0, "an inline function is not a sink")
   end)

   it("does not report a field holding a function that is not a sink", function()
      local report = findings_for([[
local function greet(x) return "hello " .. x end
local t = { run = greet }
local p = luci.http.formvalue("q")
t.run(p)
]])
      assert_equal(#report, 0, "a table of handlers is not a table of sinks")
   end)

   it("does not report a field holding an unrelated global", function()
      local report = findings_for([[
local t = { run = table.insert }
local p = luci.http.formvalue("q")
t.run(p)
]])
      assert_equal(#report, 0, "table.insert is not a dynamic-code sink")
   end)

   it("does not read a local that shadows a module name as that module", function()
      -- `local os` really does replace `os`, so the call reaches
      -- `table.insert` and not the shell. Reading it as `os.execute` is the
      -- guess; the field is the fact.
      local report = findings_for([[
local os = { execute = table.insert }
local p = luci.http.formvalue("q")
os.execute(p)
]])
      assert_equal(#report, 0, "a shadowing local is not the module it is named after")
   end)

   it("follows taint through a table field named nodes", function()
      -- The field record is keyed by field name, so a field called `nodes`
      -- has to stay taint like any other: nothing may read the record itself
      -- where a taint set is expected.
      local report = findings_for([[
local function go()
   local t = { nodes = http.formvalue("host") }
   os.execute(t.nodes)
end
]])
      assert_equal(#report, 1, "expected exactly one 709 finding")
      assert_equal(report[1].code, "709")
      assert_equal(report[1].name, "os.execute")
   end)

   it("still reports a literal string key, which is not a computed dispatch", function()
      local report = findings_for([[
local t = { run = loadstring }
local p = luci.http.formvalue("q")
t["run"](p)
]])
      local finding = only(report)
      assert_equal(finding.code, "710")
      assert_equal(finding.name, "loadstring")
   end)
end)

describe("what an alias already reached before this change", function()
   it("reports a bare-global sink aliased to a local with no table hop", function()
      -- Not a new guarantee. It is pinned here because it is the shape the
      -- table-hop case is built on: if this ever goes silent the table case
      -- cannot be right either.
      local report = findings_for([[
local L = loadstring
local p = luci.http.formvalue("q")
L(p)
]])
      local finding = only(report)
      assert_equal(finding.code, "710")
      assert_equal(finding.name, "loadstring")
   end)

   it("reports an exec sink aliased to a local, which already worked", function()
      -- `os.execute` is a field access, not a bare global, and the resolver
      -- already chased it. Recorded so the difference stays visible: the hole
      -- was bare globals only, and exec sinks did not share it.
      local report = findings_for([[
local E = os.execute
local p = luci.http.formvalue("q")
E(p)
]])
      local finding = only(report)
      assert_equal(finding.code, "709")
      assert_equal(finding.name, "os.execute")
   end)

   it("reports an exec sink reached through a field of a required module", function()
      local report = findings_for([[
local ffi = require("ffi")
local p = luci.http.formvalue("q")
ffi.C.system(p)
]])
      assert_true(#report >= 1,
         "a required module's C table is still recognised as ffi")
   end)
end)