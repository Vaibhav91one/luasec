-- Nothing here writes a configuration file. `set` is an ordinary method name
-- and appears on tables, key/value stores and encoders; reading those as config
-- writes is what produced six false positives in the verifier's probe.
local encoder = {}
encoder.add = function(name, value) return name .. value end
encoder.add("X-Token", "AAAA1234BBBB5678")

local store = {}
function store:set(key, value) end
store:set("key", "AAAA1234BBBB5678")

local helper = {}
helper.set = function(k, v) return v end
helper.set("password", "aabbccdd11223344")
