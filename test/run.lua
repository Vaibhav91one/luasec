-- Test entry point:  lua test/run.lua [dir ...]
package.path = "./test/?.lua;" .. package.path
local harness = require "harness"

local dirs = {}
for i = 1, select("#", ...) do
   table.insert(dirs, (select(i, ...)))
end
if #dirs == 0 then
   dirs = { "test/spec", "test/adversarial" }
end

local _, failures = harness.run(dirs)
os.exit(#failures == 0 and 0 or 1)
