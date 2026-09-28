-- Fixture: a decoy. Its name is not the one the handler requires, so binding
-- the handler's request parameter into it would be a guess.
local M = {}

function M.run(cmd)
   os.execute(cmd)
end

return M
