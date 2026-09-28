-- Fixture: pre-shared keys written into a program as table fields (747).
local wifi = {
   ssid = "backyard-ap",
   psk = "hunter2000",
}

local uci_defaults = {
   apikey = "9f2c41ab77de3058",
   key = "b41d8ef2a97c",
}

return {wifi = wifi, defaults = uci_defaults}
