-- One exported function, four execution sinks, none of whose arguments anything
-- in this file feeds. Each exposure is its own fact about the file and each one
-- is reported at the function, so this is the shape that made a report print
-- one line four times over (#261).
local m = {}

function m.action(arg)
   os.execute("ping -c1 " .. arg)
   os.execute("traceroute " .. arg)
   os.execute("nslookup " .. arg)
   os.execute("arp -n " .. arg)
   return "ok"
end

return m
