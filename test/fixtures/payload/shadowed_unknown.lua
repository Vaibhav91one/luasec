-- Fixture: a `load` this file defines, fed a decoded blob, whose own body never
-- shows a code loader. The name says evaluation and the chain says decoding,
-- but the definition is what decides, and this one does not say.
local encoded = "b2NobyBoaQ=="

local staged = {}

function load(chunk, chunkname)
	staged[#staged + 1] = {chunk = chunk, chunkname = chunkname}
	return staged[#staged]
end

local function stage()
	local payload = base64decode(encoded)
	return load(payload, "=stage")
end

return stage