-- docs/usage.md walks a CGILua backend through with real output pasted from the
-- tool. Output that has quietly stopped being what the tool prints is worse than
-- none, so both pasted blocks are checked against a run.
local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_equal, assert_true = harness.assert_equal, harness.assert_true

local function read(path)
   local handle = assert(io.open(path, "r"))
   local text = handle:read("*a")
   handle:close()
   return text
end

local function run(args)
   local pipe = assert(io.popen("./bin/luasec --no-progress " .. args .. " 2>/dev/null"))
   local out = pipe:read("*a")
   pipe:close()
   return (out:gsub("\n+$", ""))
end

-- The fenced block that follows the line `command` in the section.
local function pasted_after(section, command)
   local at = section:find(command, 1, true)
   assert_true(at ~= nil, "the docs no longer show: " .. command)
   -- Fences are paired from the start of the section, so the closing fence of
   -- the `sh` block is never read as the opening of the next one.
   for start, lang, block in section:gmatch("()```(%w*)\n(.-)\n```") do
      if start > at and lang == "" then return block end
   end
end

describe("the CGILua walkthrough in docs/usage.md", function()
   local text = read("docs/usage.md")
   local section = text:match("## A CGILua backend, end to end\n(.-)\n### What a CGILua scan does not follow")
   local fixture = "test/fixtures/cgilua_example"

   it("pastes what --std cgilua --whole-program prints", function()
      assert_true(section ~= nil, "the section is missing")
      local pasted = pasted_after(section, "bin/luasec --std cgilua --whole-program " .. fixture)
      assert_equal(pasted, run("--std cgilua --whole-program " .. fixture))
   end)

   it("pastes what the same scan prints without --whole-program", function()
      local pasted = pasted_after(section, "Without `--whole-program`")
      assert_equal(pasted, run("--std cgilua " .. fixture))
   end)
end)
