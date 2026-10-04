-- Fixture: a staged loader behind a shadowed name. `load` is defined by this
-- file and hands its argument straight to the standard `loadstring`, and the
-- value it is handed was decoded here. The name is a heuristic; the definition
-- is what proves the code is evaluated.
local encoded = "b2NobyBoaQ=="

function load(chunk, chunkname)
	if type(chunk) ~= "string" then
		return nil, "bad chunk"
	end
	return loadstring(chunk, chunkname or "=payload")
end

local function stage()
	local payload = base64decode(encoded)
	return load(payload, "=stage")
end

return stage