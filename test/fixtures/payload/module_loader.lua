-- Fixture: a module loader that shadows the standard `load`, which is the shape
-- of luci-base's cbi.lua. The name is `load` and the value handed to it is read
-- out of a table, but the definition resolves to `loadfile`: this compiles a
-- module off disk. Nothing here decodes a hidden payload.
local cbidir = "/usr/lib/lua/luci/model/cbi/"

function load(cbimap, ...)
	local func, err = loadfile(cbidir .. cbimap .. ".lua")
	if not func then
		func, err = loadfile(cbimap)
	end
	if not func then
		err = string.format("module %q not found: %s", cbimap, tostring(err))
	end
	return func, err
end

function Compound(...)
	return {__compound = true, fields = {...}}
end

local Delegator = {}
Delegator.__index = Delegator

function Delegator:set(name, node)
	self.nodes[name] = node
	return node
end

function Delegator:get(name)
	local node = self.nodes[name]

	if type(node) == "string" then
		node = load(node, name)
	end

	if type(node) == "table" and getmetatable(node) == nil then
		node = Compound(unpack(node))
	end

	return node
end

return Delegator