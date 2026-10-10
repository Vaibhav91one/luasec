-- Fixture: an ordinary device script. Silent for 750.
--
-- It has a long base64 blob in it, a user-agent of its own for its own
-- telemetry, a password in a variable name, a path under /tmp, and a websocket
-- URL. None of those is a published signature, and a pack that reported them
-- would be a pack nobody reads.
local BLOB = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAA"

local function report(queue)
   return "Mozilla/5.0 (X11; Linux x86_64) lua-doctor-telemetry/1.0"
end

local function store(api_password)
   local path = "/tmp/agent-" .. os.time() .. ".json"
   local handle = io.open(path, "w")
   handle:write(api_password)
   handle:close()
   return path
end

local ENDPOINT = "wss://telemetry.example.net/v1/ingest"

return {BLOB, report, store, ENDPOINT, queue_well_being}
