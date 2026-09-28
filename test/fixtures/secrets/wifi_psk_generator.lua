-- Fixture: a WiFi config generator with the network PSK in the program (747).
--
-- A true positive: the pre-shared key the installer writes into
-- /etc/config/wireless is the same key the firmware image already contains.
local uci = require "luci.model.uci"
local cursor = uci.cursor()

local GUEST_SSID = "guest-ap"
local guest_psk = "correcthorsebattery9"

local function write_guest_network()
   cursor:set("wireless.guest", "ssid", GUEST_SSID)
   cursor:set("wireless.guest", "encryption", "psk2")
   cursor:set("wireless.guest", "key", guest_psk)
   cursor:commit("wireless")
end

return write_guest_network
