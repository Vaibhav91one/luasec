-- Fixture: the paths a firmware script hands its TLS library (no 747).
--
-- Naming the file a certificate or a key lives in is not carrying the file. A
-- CA bundle on a router is public; the private key that uses it is a mode 0600
-- file the image does not contain. Both are the shape this fixture is for, and
-- the value in each is a path rather than a secret.
local CA_BUNDLE = "/etc/ssl/certs/ca-certificates.crt"
local CA_KEY = "/etc/ssl/private/ssl-cert.key"
local RELATIVE = "certs/luci-ca.pem"
local FETCHED = "https://downloads.example.net/ca-bundle.crt"

local function paths()
   return {CA_BUNDLE, CA_KEY, RELATIVE, FETCHED}
end

return paths
