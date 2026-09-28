-- Fixture: a PEM private key embedded in the source itself (747).
local deploy_key = [[-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAv7dQ2p1sXn8FkLmZ0rTbYc9WqEjH3uOvNxA5bCdEfGhIjKlMn
OpQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGh
-----END RSA PRIVATE KEY-----]]

local function publish(target)
   return target, deploy_key
end

return publish
