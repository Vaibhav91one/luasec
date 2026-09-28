-- Fixture: qualifying credential names holding values that are recognizably not
-- secrets (no 747).
--
-- Every name here is unambiguous - `password`, `private_key`, `api_key`, `psk`
-- - so the name is the evidence and the value is what has to rule it out. A
-- path is a place the key is, a URL is where it is fetched from, a format
-- string is assembled at run time, an all-caps token is a mode, a number is a
-- length or a port, and a bare word from the protocol table is a choice.
local settings = {
   password = "/etc/shadow",
   private_key = "https://keys.example.net/device.pem",
   token = "%s:%s@%s",
   api_key = "WPA2",
   psk = "wpa",
   secret = "12345678",
   passphrase = "sha256",
   credential = "none",
   privkey_pwd = "N",
}

local tls = {
   privatekey = "-----BEGIN ",
   apikey = "www.example.com",
}

return {settings = settings, tls = tls}
