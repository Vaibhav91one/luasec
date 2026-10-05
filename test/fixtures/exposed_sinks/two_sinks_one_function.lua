-- The same shape, but the two exposures name DIFFERENT sinks. They land on one
-- location and the sentence reads the same either way, and they are not the same
-- finding: `sink` is a field on the report contract and it is not the same here.
-- A merge that ignored it would drop a real observation.
local m = {}

function m.action(arg)
   os.execute("ping -c1 " .. arg)
   luci.sys.call("traceroute " .. arg)
   return "ok"
end

return m
