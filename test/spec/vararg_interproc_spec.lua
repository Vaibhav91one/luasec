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
--
-- The request data is a local named `untrusted` because that is what
-- `opts.sources` declares: a declared source is matched against a local's name,
-- not a global's. Tainting the *caller's own* vararg is #226's subject and has
-- its own spec; what is under test here is the hop after it.
local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true, assert_match = harness.assert_equal, harness.assert_true, harness.assert_match

local api = require "luasec.api"

local FIXTURE = "test/fixtures/vararg_interproc/dispatcher_forward.lua"
local RULES = "test/fixtures/vararg_interproc/dispatcher_rules.lua"

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

local function count_of(report, code)
   local n = 0
   for _, finding in ipairs(report) do
      if finding.code == code then n = n + 1 end
   end
   return n
end

describe("vararg taint across a call", function()
   it("reports an argument bound to a callee that reads its vararg", function()
      local report = api.check_source([[
local untrusted = "request"
local function run(...)
   os.execute(table.concat({...}, " "))
end
local function entry_point(...)
   run(untrusted, ...)
end
entry_point("x")
]], REQUEST)
      assert_equal(codes(report), "709", "the forwarded value reaches the sink")
      assert_equal(of(report, "709").name, "os.execute")
   end)

   it("names the request data as the source of a forwarded flow", function()
      local report = api.check_source([[
local untrusted = "request"
local function run(...)
   os.execute(table.concat({...}, " "))
end
local function entry_point(...)
   run(untrusted, ...)
end
entry_point("x")
]], REQUEST)
      assert_equal(of(report, "709").source, "declared:untrusted",
         "the finding still cites where the data came from, not the hop")
   end)

   it("keeps a forwarded vararg at the source's own confidence", function()
      -- The decision, stated as behavior rather than left implicit. A hop does
      -- not change what the data *is*, and the binding is demand-driven: what
      -- lands on the callee's vararg is read only when the callee evaluates its
      -- `...`, which is the negative below. Discounting here would charge for a
      -- path length rather than for a piece of missing evidence.
      local report = api.check_source([[
local untrusted = "request"
local function run(...)
   os.execute(table.concat({...}, " "))
end
local function entry_point(...)
   run(untrusted, ...)
end
entry_point("x")
]], REQUEST)
      assert_equal(of(report, "709").confidence, "high")
   end)

   it("does not let a callee's vararg taint flow back into its caller", function()
      -- Binding runs one way. A caller that hands a clean value to a callee, and
      -- reads its own vararg afterwards, keeps a clean vararg.
      local report = api.check_source([[
local untrusted = "request"
local function run(...)
   os.execute(table.concat({...}, " "))
end
local function entry_point(...)
   run(untrusted)
   os.execute(...)
end
entry_point("x")
]], REQUEST)
      assert_equal(count_of(report, "709"), 1,
         "one sink is fed, and the caller's own vararg stays clean")
   end)
end)

describe("a callee that ignores its vararg", function()
   it("does not taint a formal the call left clean", function()
      -- The whole risk of threading varargs through bind_call. `...` is bound,
      -- `a` is not, and nothing downstream of `a` may be tainted.
      local report = api.check_source([[
local untrusted = "request"
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

   it("does not report a sink fed only by the formal the call left clean", function()
      local report = api.check_source([[
local untrusted = "request"
local function g(a, ...)
   os.execute(a)
end
local function entry_point()
   g("clean", untrusted)
end
entry_point()
]], REQUEST)
      -- Asserted on 709 alone, not on the whole code list. The point of this
      -- spec is that binding a vararg taints the vararg and nothing else, and a
      -- 708 alongside it says nothing either way about that.
      --
      -- It appeared here in #281 and is not a regression: 708 is withheld only
      -- for a function this file calls with an argument it cannot fold to a
      -- constant, and `g("clean", untrusted)` is two constants. That tightening
      -- is deliberate -- a resolved call to an *exported* handler is no evidence
      -- that nothing outside the file calls it -- and it reaches local functions
      -- too. That 708 fires on a local function at all is older than this PR:
      -- a local that is never called reports 708 on `main` as well. Whether 708
      -- belongs on a function no other file can reach is its own question and is
      -- left where it is.
      assert_equal(of(report, "709") == nil, true,
         "the sink reads a clean formal, so it stays the shape-only 701; got " .. codes(report))
   end)

   it("reports nothing for a callee that never reads its vararg", function()
      local report = api.check_source([[
local untrusted = "request"
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
local untrusted = "request"
local function sink_fn(...)
   os.execute(table.concat({...}, " "))
end
local function middle(...)
   sink_fn(...)
end
local function entry_point(...)
   middle(untrusted)
end
entry_point("x")
]], REQUEST)
      assert_equal(codes(report), "709")
   end)

   it("reports one finding per sink when a function forwards to two callees", function()
      local report = api.check_source([[
local untrusted = "request"
local function a_fn(...)
   os.execute(table.concat({...}, " "))
end
local function b_fn(...)
   os.execute(table.concat({...}, " "))
end
local function entry_point(...)
   a_fn(untrusted)
   b_fn(untrusted)
end
entry_point("x")
]], REQUEST)
      assert_equal(count_of(report, "709"), 2, "two sinks, two findings, and neither doubled")
   end)

   it("does not repeat the same sink when the same vararg is forwarded twice", function()
      local report = api.check_source([[
local untrusted = "request"
local function sink_fn(...)
   os.execute(table.concat({...}, " "))
end
local function entry_point(...)
   sink_fn(untrusted)
   sink_fn(untrusted)
end
entry_point("x")
]], REQUEST)
      assert_equal(count_of(report, "709"), 1, "one sink, one finding")
   end)
end)

describe("a forward that lands past a callee's positional formals", function()
   -- `sink_fn("fixed", "also fixed", ...)` hands the callee two constants and
   -- then everything the caller had. The callee takes two positional arguments
   -- before its vararg, so the forwarded values fill those two *and* run on into
   -- `...`. Binding only the arguments past the last formal misses it.
   local WIDE = "test/fixtures/vararg_interproc/wide_callee_forward.lua"
   local WIDE_RULES = "test/fixtures/vararg_interproc/dispatcher_wide_callee_rules.lua"

   it("reports a sink fed by a vararg forwarded past the callee's formals", function()
      local report = api.analyze({WIDE}, {rules = {WIDE_RULES}})
      assert_equal(codes(report), "709")
   end)

   it("cites the handler the forwarded values came from", function()
      local report = api.analyze({WIDE}, {rules = {WIDE_RULES}})
      local finding = of(report, "709")
      assert_true(finding ~= nil, "expected a 709, got " .. codes(report))
      assert_match(finding.source, "handler")
   end)

   it("leaves the two constants the caller passed untainted", function()
      -- The same over-approximation a vararg always carries: the callee's
      -- positional arguments are fixed strings and the sink does not read them,
      -- so nothing beyond the one sink is reported.
      local report = api.analyze({WIDE}, {rules = {WIDE_RULES}})
      assert_equal(count_of(report, "709"), 1, "one sink, one finding")
   end)
end)

describe("vararg taint in the dispatcher shape", function()
   -- The real case, from luci-app-commands' controller. #226 already reports the
   -- handler's own `{...}`; what it could not see is anything past the forward,
   -- so the sink reported the shape and nothing about where its argument came
   -- from.
   --
   -- A rules file rather than `{std = "luci"}` on purpose. The luci profile
   -- declares `{pattern = "*", file = "*/controller/*.lua"}`, so every function
   -- in a controller file is itself an entry point: a controller fixture reports
   -- this 709 from `execute_command`'s own seeded vararg and passes with or
   -- without the binding, which is a test that cannot fail. The rules file names
   -- one entry point, so the forward is the only route to the sink.
   local function dispatcher_report()
      return api.analyze({FIXTURE}, {rules = {RULES}})
   end

   it("reports a handler's forwarded vararg reaching a command-execution sink", function()
      local report = dispatcher_report()
      local finding = of(report, "709")
      assert_true(finding ~= nil, "expected a 709, got " .. codes(report))
      assert_equal(finding.name, "os.execute")
   end)

   it("cites the handler's vararg rather than an empty source", function()
      local report = dispatcher_report()
      local finding = of(report, "709")
      assert_true(finding ~= nil, "expected a 709, got " .. codes(report))
      assert_match(finding.source, "action_run", "the source names the handler the data came from")
   end)

   it("reports the sink at the confidence the dispatcher entry declares", function()
      -- The entry declares medium, and a forward does not promote it: the hop
      -- changes where the value is read, not how much is known about what it is.
      local report = dispatcher_report()
      local finding = of(report, "709")
      assert_true(finding ~= nil, "expected a 709, got " .. codes(report))
      assert_equal(finding.confidence, "medium")
   end)

   it("reaches the sink across two forwards, not one", function()
      -- The finding sits on the sink inside execute_command, so it can only be
      -- there if action_run's vararg crossed both execute_command and
      -- parse_cmdline. Quoting the source pins which handler it started in.
      local report = dispatcher_report()
      local finding = of(report, "709")
      assert_true(finding ~= nil, "expected a 709, got " .. codes(report))
      assert_match(finding.source, "vararg", "the seed is the handler's vararg")
   end)
end)