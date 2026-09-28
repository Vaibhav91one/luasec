-- An rpcd plugin: a ubus object whose methods anyone on the network can call.
local ubus = require "ubus"

local object = ubus.add("luci.example")

local function doApply(self, data)
   os.execute(data.command)
end

object.doApply = doApply
object.ping = function(self, data)
   io.popen(data.target)
end

return object
