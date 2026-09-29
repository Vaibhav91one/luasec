local harness = require "harness"
local describe, it = harness.describe, harness.it
local assert_true = harness.assert_true

local api = require "luasec.api"

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
