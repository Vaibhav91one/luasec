-- More targets than values. `values[2]` is nil here, and reading a field of it
-- raised inside the secrets rule: every 741-749 finding in the file was replaced
-- by "a rule failed to run". It is the commonest shape in firmware - a function
-- returns several values and the caller keeps one.
local t = {}

t.a, t.b = 1

local function parse(f, line, name)
   return line, name, 0
end

local block, modulename
block.code, modulename = parse(f, block, modulename)
block, modulename = block, modulename

os.execute(cmd)

return t
