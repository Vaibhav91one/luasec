-- Fixture: CGILua page body. Request data arrives in the global `cgi`
-- table and reaches a shell through the vendor wrapper.
local host = cgi["host"]
util.runShellCmd("ping -c1 " .. host, "/tmp/out", "/tmp/err", {})
