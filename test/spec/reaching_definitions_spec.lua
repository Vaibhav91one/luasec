-- #229: a variable overwritten with a constant is that constant at the use, whatever it held
-- before, so the constant-argument rule must see the definition that REACHES the use. The tainted
-- cases beside it are the half that matters more: a value that may still be untrusted must be
-- reported exactly as before. The fold only trusts the reaching definition when it is the only one
-- and no closure writes the variable, because a closure's write happens when it runs.
local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal = harness.assert_equal

local api = require "luadoctor.api"

local function codes(source)
   local out = {}
   for _, finding in ipairs(api.check_source(source, {std = "luci"})) do
      if finding.code:match("^70[19]$") then out[#out + 1] = finding.code end
   end
   table.sort(out)
   return table.concat(out, ",")
end

describe("a constant overwrite kills the taint at the use (#229)", function()
   it("reports nothing for a tainted local overwritten with a constant before the sink", function()
      assert_equal(codes([[
local p = luci.http.formvalue("q")
local c = p
c = "safe"
os.execute("echo " .. c)
]]), "", "the value at the sink is the constant")
   end)

   it("reports the same as a never-tainted constant, which is nothing", function()
      assert_equal(codes('local c = "safe"\nos.execute("echo " .. c)\n'), "")
   end)

   it("still reports a value that a branch may have left tainted", function()
      assert_equal(codes([[
local p = luci.http.formvalue("q")
local c = "safe"
if p then c = p end
os.execute("echo " .. c)
]]), "709")
   end)

   it("still reports a value a closure may have made tainted", function()
      assert_equal(codes([[
local c = "safe"
local function f() c = luci.http.formvalue("x") end
f()
os.execute("echo " .. c)
]]), "709")
   end)

   it("still reports a value a loop may have made tainted", function()
      assert_equal(codes([[
local c = "safe"
for i = 1, 2 do
   os.execute("x " .. c)
   c = luci.http.formvalue("q")
end
]]), "709")
   end)

   it("still reports an overwrite that is not a constant", function()
      assert_equal(codes([[
local p = luci.http.formvalue("q")
local c = p
c = p .. "x"
os.execute("echo " .. c)
]]), "709")
   end)

   it("a constant overwrite of an untainted non-constant is a constant too", function()
      assert_equal(codes([[
local c = os.getenv("HOME")
c = "safe"
os.execute("echo " .. c)
]]), "", "no 701 for a value that is the literal at the sink")
   end)

   -- The cases above are tainted, so a 709 would be reported whether or not the constant fold
   -- trusted the wrong definition. These use an untracked source (an unknown function), so only the
   -- 701 stands between the value and a silent pass: they are the ones that detect a false fold.
   it("keeps the 701 when a closure may overwrite the variable before the sink", function()
      assert_equal(codes([[
local c = "b"
local function f() c = unknown_fn() end
f()
os.execute("echo " .. c)
]]), "701")
   end)

   it("keeps the 701 when a closure is defined after the declaration and called in between", function()
      assert_equal(codes([[
local c = "b"
c = "a"
local function f() c = unknown_fn() end
f()
os.execute("echo " .. c)
]]), "701")
   end)

   it("keeps the 701 when a pcall'd function overwrites the variable", function()
      assert_equal(codes([[
local c = "b"
pcall(function() c = unknown_fn() end)
os.execute("echo " .. c)
]]), "701")
   end)

   it("keeps the 701 for a function parameter", function()
      assert_equal(codes([[
local function go(c)
   os.execute("echo " .. c)
end
]]), "701")
   end)

   it("keeps the 701 when only one branch overwrites with a constant", function()
      assert_equal(codes([[
local c = unknown_fn()
if other_fn() then c = "safe" end
os.execute("echo " .. c)
]]), "701")
   end)
end)
