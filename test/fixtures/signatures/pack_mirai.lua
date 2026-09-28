-- Fixture: a scanner carrying three known Mirai signatures (750).
--
-- The credential table, the User-Agent every scan request carries, and the
-- name the binary installs itself under. Any one of them is a claim about where
-- this file came from.
local CREDENTIALS = {
   {user = "root", password = "vizxv"},
   {user = "admin", password = "xc3511"},
}

local USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36"

local LOADER = "/tmp/.mirai"

local function start()
   os.execute("/bin/busybox MIRAI " .. LOADER)
   return #CREDENTIALS, USER_AGENT
end

return start
