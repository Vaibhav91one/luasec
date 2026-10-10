local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_match, assert_true =
   harness.assert_equal, harness.assert_match, harness.assert_true

local api = require "luadoctor.api"

describe("lua-doctor rules", function()
   it("lists every registered code with its category, severity and cwe", function()
      local out, code = harness.cli({"rules", "list"})
      assert_equal(code, 0, out)
      for _, rule in ipairs(api.rule_catalogue()) do
         assert_match(out, "\n?" .. rule.code .. "  " .. rule.category, "missing " .. rule.code)
      end
      assert_match(out, "709  exec      critical  CWE%-78   untrusted data reaches command execution\n", out)
   end)

   it("lists with no subcommand too", function()
      local listed = harness.cli({"rules", "list"})
      local bare = harness.cli({"rules"})
      assert_equal(bare, listed, "lua-doctor rules is lua-doctor rules list")
   end)

   it("explains a code by printing its doc page", function()
      local out, code = harness.cli({"rules", "explain", "709"})
      assert_equal(code, 0, out)
      local page = assert(io.open("docs/rules/709.md")):read("*a")
      assert_equal(out:gsub("%s+$", ""), page:gsub("%s+$", ""), "the page, unchanged")
   end)

   it("refuses a code that does not exist", function()
      local out, code = harness.cli({"rules", "explain", "799"})
      assert_equal(code, 2, out)
      assert_match(out, "unknown code '799'", out)
   end)

   it("refuses explain without a code and an unknown subcommand", function()
      local out, code = harness.cli({"rules", "explain"})
      assert_equal(code, 2, out)
      assert_match(out, "needs a code", out)
      out, code = harness.cli({"rules", "show"})
      assert_equal(code, 2, out)
      assert_match(out, "expected list, explain, set, enable or disable", out)
   end)

   it("still scans a directory named rules when given as a path", function()
      local out, code = harness.cli({"./test/fixtures/clean"})
      assert_equal(code, 0, out)
      assert_true(not out:match("unknown rules command"), out)
   end)
end)
