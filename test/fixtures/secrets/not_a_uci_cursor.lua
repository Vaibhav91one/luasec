-- A library whose object is also called a cursor, and helper tables with a
-- method called set. Neither writes a configuration file.
local store = {}
store.cursor = function() return {} end
local handle = store.cursor()
handle:set("password", "0123456789abcdef0123")

local encoder = {}
encoder.add = function(name, value) return name .. value end
encoder.add("X-Token", "AAAA1234BBBB5678")

local kv = {}
function kv:set(key, value) end
kv:set("key", "AAAA1234BBBB5678")

local helper = {}
helper.set = function(k, v) return v end
helper.set("password", "aabbccdd11223344")
