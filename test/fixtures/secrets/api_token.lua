-- Fixture: an API token written into the program (747).
--
-- A true positive, and the name is in capitals, which is how firmware spells
-- one. `API_TOKEN` is a credential in its own right: the token is read out of
-- the image by anyone who unzips it.
local API_TOKEN = "ghp_4eC39Jqklj3nR2vB8sY1wZ5"

local function authorization()
   return "Bearer " .. API_TOKEN
end

return authorization
