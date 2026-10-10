local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_true = harness.assert_true

local api = require "luadoctor.api"

local function read(path)
   local handle = io.open(path, "r")
   if not handle then return nil end
   local text = handle:read("*a")
   handle:close()
   return text
end

describe("rule doc pages", function()
   it("has a page for every registered code with the required sections", function()
      for _, rule in ipairs(api.rule_catalogue()) do
         local path = "docs/rules/" .. rule.code .. ".md"
         local page = read(path)
         assert_true(page, path .. " is missing")
         assert_true(page:find("^# " .. rule.code .. " "), path .. " must start with '# " .. rule.code .. " '")
         for _, heading in ipairs({"## What it means", "## Example", "## How to fix", "## Fix prompt"}) do
            assert_true(page:find(heading, 1, true), path .. " has no '" .. heading .. "' section")
         end
         assert_true(page:find("```prompt\n", 1, true), path .. " has no ```prompt fenced block")
         assert_true(page:find(rule.severity, 1, true) or rule.code == "708",
            path .. " does not state the severity " .. rule.severity)
      end
   end)

   it("gives an example that fires its own code", function()
      for _, rule in ipairs(api.rule_catalogue()) do
         local page = read("docs/rules/" .. rule.code .. ".md")
         local section = page and page:match("## Example\n(.-)\n## ")
         local example = section and section:match("```lua\n(.-)```")
         if example then
            local std = section:match("`%-%-std (%S+)`")
            local fired = false
            for _, finding in ipairs(api.check_source(example, {std = std})) do
               if finding.code == rule.code then fired = true end
            end
            assert_true(fired, "the example in docs/rules/" .. rule.code .. ".md does not fire "
               .. rule.code)
         end
      end
   end)
end)

describe("708 documented confidence matches what is emitted (#231)", function()
   it("states in docs/rules/708.md the confidence that every emitted 708 carries", function()
      local page = read("docs/rules/708.md")
      assert_true(page, "docs/rules/708.md is missing")
      local documented = page:match("Confidence: (%a+)")
      assert_true(documented, "docs/rules/708.md has no 'Confidence: <level>' line")
      local report = api.check_source(
         "function h(x)\n  luci.sys.call(\"/bin/foo \" .. x)\nend\nreturn h\n", {std = "luci"})
      local seen = 0
      for _, finding in ipairs(report) do
         if finding.code == "708" then
            seen = seen + 1
            assert_true(finding.confidence == documented,
               "docs/rules/708.md says Confidence: " .. documented .. " but a 708 is emitted at " ..
               tostring(finding.confidence))
         end
      end
      assert_true(seen > 0, "the reproduction no longer emits a 708, so this spec checks nothing")
   end)
end)
