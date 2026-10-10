describe("numeric constants", function()
   it("folds arithmetic over literals", function()
      local api = require "luasec.api"
      -- If folding were broken here, this would look like a dynamic command and
      -- be reported; a fixed command is not a finding.
      local report = api.check_source([[
local function go()
   os.execute("count " .. (1 + 2) .. " items")
end
]])
      assert_equal(#report, 0, "a command built by arithmetic on literals is still constant")
   end)

   it("reports a command that mixes a literal with a computed number", function()
      local api = require "luasec.api"
      local report = api.check_source([[
local function go(n)
   os.execute("count " .. (n + 2) .. " items")
end
]])
      assert_true(#report > 0, "a computed value is not a constant")
   end)
end)

describe("local constants", function()
   it("reports nothing when a command argument is a local bound once to a literal", function()
      local api = require "luasec.api"
      local report = api.check_source([[
local STTY_COOKED = "stty -echo"
os.execute(STTY_COOKED)
]])
      assert_equal(#report, 0,
         "a local assigned once to a literal is a constant, not a dynamic command")
   end)

   it("still reports a command argument whose local is reassigned before the call", function()
      local api = require "luasec.api"
      -- The literal is only where it starts. Stopping the chase at the first
      -- definition would trade a false positive for a false negative, and a
      -- 701 that stays silent when the value is unknown is worse than one that
      -- cries wolf.
      local report = api.check_source([[
local function go(dynamic)
   local X = "a"
   X = dynamic
   os.execute(X)
end
]])
      assert_true(#report > 0, "a local reassigned before the call is not a constant")
   end)

   it("still reports a command argument read out of a table field", function()
      local api = require "luasec.api"
      -- A local bound to a table is deliberately not folded. Whether M.cmd still
      -- holds the literal depends on every write to M, including writes through
      -- an index key, a metatable, or a function lua-doctor cannot see from this one
      -- definition. Answering "yes" would need a write set for the table, so
      -- table state stays dynamic.
      local report = api.check_source([[
local M = {}
M.cmd = "stty -echo"
os.execute(M.cmd)
]])
      assert_true(#report > 0, "a field of a table is not a constant the fold can prove")
   end)

   it("still reports a command argument read from a table built in one constructor", function()
      local api = require "luasec.api"
      -- Same decision, other spelling: folding this would mean modelling the
      -- constructor's keys and then proving nothing else wrote to the table.
      local report = api.check_source([[
local M = { cmd = "stty -echo" }
os.execute(M.cmd)
]])
      assert_true(#report > 0, "a table constructor field is not a constant the fold can prove")
   end)

   it("still reports a command argument whose local is assigned only after the declaration", function()
      local api = require "luasec.api"
      -- One assignment, but not one the use site is guaranteed to have seen. A
      -- fold that took it would have to answer "did this line run", which is a
      -- control-flow question, not a constant question.
      local report = api.check_source([[
local X
X = "stty -echo"
os.execute(X)
]])
      assert_true(#report > 0, "a value assigned after its declaration is not provably constant")
   end)

   it("terminates and still reports when a local is defined in terms of itself", function()
      local api = require "luasec.api"
      -- `local X = X` resolves the initialiser to the very variable being
      -- resolved, so a fold that does not notice it is following itself never
      -- returns. What matters is that it comes back with a finding.
      local report = api.check_source([[
local X = X
os.execute(X)
]])
      assert_true(#report > 0, "a self-referential definition is not a constant")
   end)

   it("terminates and still reports when two locals are defined in terms of each other", function()
      local api = require "luasec.api"
      local report = api.check_source([[
local X = Y
local Y = X
os.execute(X)
]])
      assert_true(#report > 0, "mutually referencing definitions are not a constant")
   end)

   it("folds a local whose literal is reached through another local", function()
      local api = require "luasec.api"
      local report = api.check_source([[
local FIRST = "stty -echo"
local SECOND = FIRST
os.execute(SECOND)
]])
      assert_equal(#report, 0, "an alias of a constant is still that constant")
   end)

   it("folds a constant captured by a function as an upvalue", function()
      local api = require "luasec.api"
      local report = api.check_source([[
local STTY_COOKED = "stty -echo"
local function go()
   os.execute(STTY_COOKED)
end
]])
      assert_equal(#report, 0,
         "a constant read from an enclosing scope is still a constant")
   end)

   it("still reports a command argument that is a global", function()
      local api = require "luasec.api"
      -- Chasing an alias must not extend to names lua-doctor never saw defined: a
      -- global is whatever another file put there.
      local report = api.check_source([[
os.execute(STTY_COOKED)
]])
      assert_true(#report > 0, "a global name is not a constant")
   end)
end)
