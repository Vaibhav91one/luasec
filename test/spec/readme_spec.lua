local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true, assert_match = harness.assert_equal, harness.assert_true, harness.assert_match

local api = require "luasec.api"

-- The README is the product's only front door: someone decides whether to trust
-- this tool by reading it. A number in it that has quietly stopped being true
-- is worse than no number, so the ones that can be checked from the tree are
-- checked. This is the same failure that ran three times in docs/precision.md,
-- in the document people are most likely to quote.
--
-- It cannot check a judgment. "Beta", "does not follow a return value" and
-- "a scan root is bounded" are claims for a reader to weigh, not assertions to
-- enforce, and a spec that pretended otherwise would only make this file
-- mechanical.

local function read(path)
   local handle = assert(io.open(path, "r"))
   local text = handle:read("*a")
   handle:close()
   return text
end

describe("the README", function()
   it("counts the rule catalogue correctly", function()
      local text = read("README.md")
      local claimed = assert(tonumber(text:match("(%d+) registered rule codes")),
         "the README does not say how many rule codes there are")
      assert_equal(claimed, #api.rule_catalogue(),
         "the README says " .. claimed .. " rule codes; the catalogue has "
            .. #api.rule_catalogue())
   end)

   it("documents only commands that exist", function()
      -- A build instruction that has been renamed is worse than no
      -- instruction, because a reader follows it and concludes the tool is
      -- broken. Every `make X` the README names has to be a real target.
      local makefile = read("Makefile")
      local text = read("README.md")

      for target in text:gmatch("make ([%w%-]+)") do
         -- A target line is `name:` at the start of a line, and this project
         -- uses one dash for the gate's name on the command line and one in
         -- the rule itself, so the target is matched literally.
         -- A PLAIN find. In a Lua pattern the dash in `ci-verify` is a lazy
         -- quantifier applied to the `i` before it, so the pattern does not match
         -- the target it is looking for - and two of this project's targets have
         -- a dash in the name.
         local defined = makefile:find("\n" .. target .. ":", 1, true) ~= nil
         assert_true(defined, "the README says `make " .. target
            .. "` and the Makefile has no such target")
      end
   end)

   it("quotes the same measurement the precision gate checks", function()
      -- The headline number. docs/precision.md and scripts/precision-golden.lua
      -- are both checked against each other and against a real run; the README
      -- quotes the same figure and is the one most likely to be read.
      local text = read("README.md")
      local golden = dofile("scripts/precision-golden.lua")
      local claimed = assert(tonumber(text:match("Findings | %*%*(%d+)%*%* across")),
         "the README does not state the finding count it measured")
      assert_equal(claimed, golden.total,
         "the README quotes " .. claimed .. " findings; the frozen measurement is "
            .. golden.total)
   end)

   it("states the exit codes the CLI actually defines", function()
      local text = read("README.md")
      for _, code in ipairs({"0", "1", "2", "3"}) do
         assert_true(text:find("`" .. code .. "`", 1, true) ~= nil,
            "the README does not document exit code " .. code)
      end
   end)

   it("does not claim to cover what the tool documents as out of scope", function()
      -- The failure mode this file exists to prevent is a README that grows more
      -- confident than the code. If the out-of-scope list in
      -- docs/architecture.md gains an item, the README has to acknowledge it.
      local text = read("README.md")
      local scope = read("docs/architecture.md")
      local out_of_scope = scope:match("## What is out of scope(.*)$")

      assert_true(out_of_scope ~= nil, "the out-of-scope section is where it says it is")
      for _, limit in ipairs({"return value", "decompiled"}) do
         if out_of_scope:find(limit, 1, true) then
            assert_true(text:find(limit, 1, true) ~= nil,
               "docs/architecture.md lists '" .. limit .. "' as out of scope and "
                  .. "the README does not mention it")
         end
      end
   end)
   it("documents the terminal options a person types", function()
      local text = read("README.md")
      for _, flag in ipairs({"--interactive", "--no-interactive", "--view doctor", "--progress"}) do
         assert_true(text:find(flag, 1, true) ~= nil,
            "the README does not document " .. flag)
      end
   end)
end)
