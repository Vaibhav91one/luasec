-- One handler, two execution sinks. The exposure is the handler, so it is one
-- finding naming the handler and the first sink, not two findings.
local ubus = require "ubus"

local object = ubus.add("luci.example")

object.apply = function(self, data)
   os.execute(data.command)
   io.popen(data.followup)
end

return object
