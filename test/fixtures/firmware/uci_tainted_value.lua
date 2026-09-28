-- The request parameter goes straight into configuration. The dataflow pass
-- already reports this statement as an untrusted-data finding; 722 must not
-- add a second finding for the same line.
local M = {}

function M.set_hostname()
   uci.set("system", "@system[0]", "hostname", luci.http.formvalue("hostname"))
   uci.commit("system")
end

return M
