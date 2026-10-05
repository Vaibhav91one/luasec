-- Which calls are call sites.
--
-- `interprocedural.bind_call` binds a call's actual arguments to the callee's
-- formals, but it can only bind a call that `callgraph.call_sites` found, and
-- that found only calls which were a whole statement. Two properties of real
-- firmware Lua fell out of that, and both had to be fixed for either to matter:
--
--   * a call whose result is *assigned* is not a whole statement, so
--     `local argv = parse_cmdline(...)` was never a site;
--   * a global `function f(x)` has no local binding to follow, so the callee
--     was never resolved -- and LuCI handlers are globals.
--
-- Either fix alone leaves the motivating file unbound, which is why the
-- combined case is specified as its own behavior rather than left to the two
-- singles to imply.
--
-- Measured on corpus/luci-1806/applications/luci-app-commands/luasrc/controller/commands.lua
-- (see the PR for the traversal): 91 Call/Invoke nodes in the file, 33 of them
-- whole-statement calls, 3 resolving to a callee before this change.
--
-- The request data is a local named `untrusted`, because that is what
-- `opts.sources` matches on -- a declared source is matched against a local's
-- name, not a global's.
local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_no_match = harness.assert_equal, harness.assert_no_match


describe("a method call on a local", function()
   it("reads its arguments instead of raising", function()
      local api = require "luasec.api"
      local handle = assert(io.open("test/fixtures/method_call_on_local.lua", "r"))
      local report = api.check_source(handle:read("*a"), {std = "+luci"})
      handle:close()

      local found = 0
      for _, finding in ipairs(report) do
         if finding.code == "901" then
            found = found + 1
            assert_no_match(finding.message or "", "number value",
               "a method call is not a crash: " .. tostring(finding.message))
         end
      end
      assert_equal(found, 0,
         "a method call with arguments is valid Lua and must not be a failure")
   end)
end)


local REQUEST = {sources = {"untrusted"}, source_confidence = "high"}

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


describe("a call whose result is assigned", function()
   it("binds the assigned arguments to a local function's formals", function()
      -- The whole statement is `local result = ...`, so this call was never
      -- visited, and the request data stopped one line short of the sink.
      local api = require "luasec.api"
      local report = api.check_source([[
local untrusted = "request"
local function execute(cmd)
   os.execute(cmd)
end
local result = execute(untrusted)
]], REQUEST)
      local hit = of(report, "709")
      assert_equal(hit and hit.name, "os.execute",
         "an argument bound through an assignment still reaches the sink")
   end)

   it("binds a plain assignment to a local function's formals", function()
      local api = require "luasec.api"
      local report = api.check_source([[
local untrusted = "request"
local function execute(cmd)
   os.execute(cmd)
end
result = execute(untrusted)
]], REQUEST)
      local hit = of(report, "709")
      assert_equal(hit and hit.name, "os.execute",
         "`x = f(tainted)` is the same shape as `local x = f(tainted)`")
   end)

   it("binds an argument returned straight out of a function", function()
      local api = require "luasec.api"
      local report = api.check_source([[
local untrusted = "request"
local function execute(cmd)
   os.execute(cmd)
end
local function outer()
   return execute(untrusted)
end
]], REQUEST)
      local hit = of(report, "709")
      assert_equal(hit and hit.name, "os.execute",
         "a call in a return position is a call like any other")
   end)

   it("binds only the tainted argument of an assigned call", function()
      -- The negative half of the fix. Binding a call does not bind everything
      -- it mentions: a constant stays constant, and `clean` must not inherit.
      local api = require "luasec.api"
      local report = api.check_source([[
local untrusted = "request"
local function execute(cmd)
   os.execute(cmd)
end
local result = execute("/usr/bin/true")
]], REQUEST)
      assert_equal(count_of(report, "709"), 0,
         "a constant argument is not untrusted data")
   end)

   it("does not bind a call to a function defined outside the file", function()
      -- Only functions defined in the analyzed file are in scope. `absent` is
      -- not defined here, so there is no body to bind into and nothing to say
      -- about what it does with the argument.
      local api = require "luasec.api"
      local report = api.check_source([[
local untrusted = "request"
local result = absent(untrusted)
]], REQUEST)
      assert_equal(count_of(report, "709"), 0,
         "an unresolved callee is not a flow to a sink")
   end)
end)


describe("a global function declaration", function()
   it("resolves as a callee for a whole-statement call", function()
      -- A global `function` has no local binding, so this call site existed and
      -- still could not name a callee.
      local api = require "luasec.api"
      local report = api.check_source([[
local untrusted = "request"
function execute(cmd)
   os.execute(cmd)
end
execute(untrusted)
]], REQUEST)
      local hit = of(report, "709")
      assert_equal(hit and hit.name, "os.execute",
         "a global declaration resolves like a local one")
   end)

   it("resolves as a callee when the call is assigned", function()
      -- The LuCI shape: a global handler, called in an assignment. This needs
      -- both fixes, and it is the one that stays unbound if only one lands.
      local api = require "luasec.api"
      local report = api.check_source([[
local untrusted = "request"
function execute(cmd)
   os.execute(cmd)
end
local result = execute(untrusted)
]], REQUEST)
      local hit = of(report, "709")
      assert_equal(hit and hit.name, "os.execute",
         "a global handler called in an assignment binds its arguments")
   end)

   it("resolves a global declared after the call that reaches it", function()
      -- Declaration order is not binding order in Lua for a global: the name is
      -- resolved at call time. A dispatcher often registers its handlers in a
      -- table above the definitions themselves.
      local api = require "luasec.api"
      local report = api.check_source([[
local untrusted = "request"
local function entry()
   execute(untrusted)
end
function execute(cmd)
   os.execute(cmd)
end
]], REQUEST)
      local hit = of(report, "709")
      assert_equal(hit and hit.name, "os.execute",
         "a global declared below its call site still resolves")
   end)

   it("does not resolve a global to a same-named local's body", function()
      -- The shadowing case, and the reason the global lookup is keyed on an
      -- unshadowed Id rather than on the name alone. Inside this scope `execute`
      -- is a local, so the local's body is the callee and the global one is not.
      --
      -- The global's body passes `cmd` straight to the sink. A name-matching
      -- bug would bind `untrusted` to that `cmd` and report 709; the correct
      -- implementation binds it to the local, which discards it, and reports
      -- nothing. With a global body that dropped the argument instead this spec
      -- would pass under the bug too, and pin nothing.
      local api = require "luasec.api"
      local report = api.check_source([[
local untrusted = "request"
function execute(cmd)
   os.execute(cmd)
end
local function outer()
   local function execute(cmd)
      return cmd
   end
   local result = execute(untrusted)
end
]], REQUEST)
      assert_equal(count_of(report, "709"), 0,
         "a shadowing local's body is the callee, and it discards the value")
   end)

   it("does not resolve a global callee that the file never declares", function()
      -- `require`-style and platform callees are not in this file. Binding them
      -- would mean inventing a body, so an undeclared global stays unresolved.
      local api = require "luasec.api"
      local report = api.check_source([[
local untrusted = "request"
local result = uci_get(untrusted)
]], REQUEST)
      assert_equal(count_of(report, "709"), 0,
         "an undeclared global callee has no body here to bind into")
   end)
end)


describe("an exported handler the file also calls with a constant", function()
   it("still reports the sink as exposed", function()
      -- The hole this closes, and it is worse than a missed finding. A resolved
      -- call is not evidence that a function is fed: an exported handler's real
      -- callers are in another file, because LuCI registers it by name and
      -- dispatches to it from the dispatcher. Here the file calls `handler` with
      -- a literal, which proves nothing about the path an attacker would take.
      --
      -- Under the loosened rule the in-file call made 708 stand down and 709
      -- never stood up -- "cleanup" is a constant -- so the tool went quiet on a
      -- reachable os.execute. Both halves are asserted, because either alone is
      -- a pass: 708 is the finding, and its absence is the bug.
      local api = require "luasec.api"
      local report = api.check_source([[
function handler(cmd)
   os.execute(cmd)
end
function boot()
   handler("cleanup")
end
]], {std = "+luci"})
      assert_equal(count_of(report, "708"), 1,
         "a constant-only in-file call does not make an exported sink unexposed")
   end)

   it("stands down once a call supplies data it cannot fold", function()
      -- The other half, so the rule above cannot be satisfied by never
      -- withholding. A call with a non-constant argument means the feed is
      -- visible here, which is the case 708 was written not to double-report.
      local api = require "luasec.api"
      local report = api.check_source([[
local name = os.getenv("CMD")
function handler(cmd)
   os.execute(cmd)
end
handler(name)
]], {std = "+luci"})
      assert_equal(count_of(report, "708"), 0,
         "a traced in-file call means the feed is visible here")
   end)
end)
