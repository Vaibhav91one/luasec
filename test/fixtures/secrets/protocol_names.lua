-- Fixture: names that look like credentials holding protocol and mode vocabulary
-- (no 747).
--
-- This is the shape luci's wireless CBI model is written in: `auth` and `key`
-- named fields whose values choose an 802.11 authentication mode, and the
-- names of the things the model is describing. The name is the only word saying
-- secret and the value says the opposite.
local station = {
   ssid = "backyard-ap",
   mode = "sta",
   auth = "EAP-TLS",
   encryption = "wpa2",
}

local peer = {
   auth = "wpa-psk",
   key = "WEP",
   mode = "adhoc",
}

local cipher = {
   key = "ccmp",
   auth = "ttls",
   encryption = "tkip",
}

local certificate_field = {
   key = "commonName",
   auth = "organizationalUnitName",
}

return {station = station, peer = peer, cipher = cipher, field = certificate_field}
