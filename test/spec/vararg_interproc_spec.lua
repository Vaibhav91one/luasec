-- A vararg carries its taint into the callee it is passed to.
--
-- #226 established that a dispatcher's `...` is request data. It stopped at the
-- function that declares the vararg, because `interprocedural.bind_call` bound a
-- call's arguments to the callee's *positional* formals and a callee declared
-- `function(...)` has none. The LuCI shape this hides:
--
--     entry(..., call("action_run"))        -- URL path arrives as `...`
--     function action_run(...) execute_command(callback, ...) end
--     function execute_command(cb, ...) os.execute(parse_cmdline(...)) end
--
-- Two things have to hold for that to be worth reporting, and the second one is
-- the whole risk of the change:
--
--   * a callee that *reads* its vararg inherits what the caller put there;
--   * a callee that *ignores* it inherits nothing.
--
-- The second is what makes the first safe to state at the source's own
-- confidence, and it is specified here as behavior rather than assumed.
local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true, assert_match = harness.assert_equal, harness.assert_true, harness.assert_match

local api = require "luasec.api"

local FIXTURE = "test/fixtures/vararg_interproc/luci/controller/dispatcher_forward.lua"

-- A global the caller treats as request data. Naming it here keeps these specs
-- off any platform profile: the binding under test is engine code and every
-- profile is affected, so nothing in this file may depend on one.
local REQUEST = {sources = {"untrusted"}, source_confidence = "high"}

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

describe("vararg taint across a call", function()
   it("reports a vararg a caller forwards into a callee that reads it", function()
      local report = api.check_source([[
local function run(...)
   os.execute(select(1, ...))
end
local function entry_point(...)
   run(untrusted, "fixed")
end
entry_point("x")
]], REQUEST)
      assert_equal(codes(report), "709", "the forwarded value reaches the sink")
      assert_equal(of(report, "709").name, "os.execute")
   end)

   it("names the request data as the source of a forwarded flow", function()
      local report = api.check_source([[
local function run(...)
   os.execute(select(1, ...))
end
local function entry_point(...)
   run(untrusted, "fixed")
end
entry_point("x")
]], REQUEST)
      assert_equal(of(report, "709").source, "declared source untrusted",
         "the finding still cites where the data came from, not the hop")
   end)

   it("keeps a forwarded vararg at the source's own confidence", function()
      -- The decision, stated as behavior rather than left implicit. A hop does
      -- not change what the data *is*, and the binding is demand-driven: the
      -- descriptors on the callee's vararg are consulted only when the callee
      -- evaluates its `...`, which is the negative below. Discounting here would
      -- charge for a path length rather than for missing evidence.
      local report = api.check_source([[
local function run(...)
   os.execute(select(1, ...))
end
local function entry_point(...)
   run(untrusted, "fixed")
end
entry_point("x")
]], REQUEST)
      assert_equal(of(report, "709").confidence, "high")
   end)
end)

describe("a callee that ignores its vararg", function()
   it("does not taint a formal the forwarded call left clean", function()
      -- The whole risk of threading varargs through bind_call. `...` is bound,
      -- `a` is not, and nothing downstream of `a` may be tainted.
      local report = api.check_source([[
local function g(a, ...)
   return a
end
local function entry_point()
   g("clean", untrusted)
end
entry_point()
]], REQUEST)
      assert_true(of(report, "709") == nil, "got " .. codes(report))
   end)

   it("does not report a sink fed only by the formal a forwarded call left clean", function()
      local report = api.check_source([[
local function g(a, ...)
   os.execute(a)
end
local function entry_point()
   g("clean", untrusted)
end
entry_point()
]], REQUEST)
      assert_true(of(report, "709") == nil,
         "the sink reads a clean formal, so it stays a 701: got " .. codes(report))
   end)

   it("reports nothing for a callee that never reads its vararg", function()
      local report = api.check_source([[
local function g(...)
   return 1
end
local function entry_point()
   g(untrusted)
end
entry_point()
]], REQUEST)
      assert_equal(codes(report), "")
   end)
end)

describe("forwarding a vararg through more than one callee", function()
   it("still reports a sink two forwarding hops away", function()
      local report = api.check_source([[
local function sink_fn(...)
   os.execute(select(1, ...))
end
local function middle(...)
   sink_fn(...)
end
local function entry_point(...)
   middle(...)
end
entry_point("x")
]], REQUEST)
      assert_equal(codes(report), "709")
   end)

   it("reports one finding when a function forwards its vararg to two callees", function()
      local report = api.check_source([[
local function a_fn(...)
   os.execute(select(1, ...))
end
local function b_fn(...)
   os.execute(select(1, ...))
end
local function entry_point(...)
   a_fn(...)
   b_fn(...)
end
entry_point("x")
]], REQUEST)
      local count = 0
      for _, finding in ipairs(report) do
         if finding.code == "709" then count = count + 1 end
      end
      assert_equal(count, 2, "two sinks, two findings, and neither doubled")
   end)

   it("does not repeat the same sink when the same vararg is forwarded twice", function()
      local report = api.check_source([[
local function sink_fn(...)
   os.execute(select(1, ...))
end
local function entry_point(...)
   sink_fn(...)
   sink_fn(...)
end
entry_point("x")
]], REQUEST)
      local count = 0
      for _, finding in ipairs(report) do
         if finding.code == "709" then count = count + 1 end
      end
      assert_equal(count, 1, "one sink, one finding")
   end)
end)
describe("vararg taint in the LuCI dispatcher shape", function()
   -- The real case, from luci-app-commands' controller. #226 already reports the
   -- handler's own `{...}`; what it could not see is anything past the forward,
   -- so the sink reported the shape and nothing about where its argument came
   -- from.
   it("reports a handler's forwarded vararg reaching a command-execution sink", function()
      local report = api.analyze({FIXTURE}, {std = "luci"})
      local finding = of(report, "709")
      assert_true(finding ~= nil, "expected a 709, got " .. codes(report))
      assert_equal(finding.name, "os.execute")
   end)

   it("cites the dispatcher vararg rather than an empty source", function()
      local report = api.analyze({FIXTURE}, {std = "luci"})
      local finding = of(report, "709")
      assert_true(finding ~= nil, "expected a 709, got " .. codes(report))
      assert_match(finding.source, "vararg", "the source names the handler's vararg")
   end)

   it("reports the sink at the confidence the dispatcher entry declares", function()
      -- The LuCI profile declares its dispatcher arguments at medium, and a
      -- forward does not promote them: the hop changes where the value is read,
      -- not how much is known about what it is.
      local report = api.analyze({FIXTURE}, {std = "luci"})
      local finding = of(report, "709")
      assert_true(finding ~= nil, "expected a 709, got " .. codes(report))
      assert_equal(finding.confidence, "medium")
   end)
end)
