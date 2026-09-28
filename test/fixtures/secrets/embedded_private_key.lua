-- Fixture: a complete private key block carried in the program (747 kind pem).
--
-- A true positive. The whole block is a secret, and the finding says so without
-- quoting any of the body: the header is the only part of a PEM that is not
-- key material, and it is the only part a report may carry.
local ca_key = [[-----BEGIN RSA PRIVATE KEY-----
Lh+pclU9MvN9oH4uekt140MyQOaxHlOFrMPJLN338c88KzwzvF2TgTPPreTfwdV+
N7dMQwFX+Wc4xbpniViXkoZF00WZtU2NHUh6keyAJX6vy6HLKTA0pa/ObyFog3qS
Gem0M5ZCiNhWys/V0qiLeBZ9JXomfRQ/pReLWjTu6cihZMqU0YiuwoYB/P0ixbDY
4hZ6ZtFnLmJqIUW1Za6zXCRVVrrYnE3pIG/+sordBOaSbCXEKZ29zqbkbQGDjo/T
dYwZAsSbxUFsvmd6nI543mrW4NbnyiY5LNrILfVeuqBMfg7H0xfuWsKKvC3524Ym
7jZD8hMp1pKy/ss7Ie1MG5ZfEFtUFppE71i4K2WyaNSDaL2F/rUCRexvzb8LkEFm
RhY3SClfIrGtpXAWG8HXU9WvQsfUjsZ3h5IWOLUT33fjx/NQKcL5uBc4XdyJ7KN9
h8XogcZh22etTnTBBYKl7O/VMKj/NAQV
-----END RSA PRIVATE KEY-----]]

local function write_pem(path)
   local handle = assert(io.open(path, "w"))
   handle:write(ca_key)
   handle:close()
   return path
end

return write_pem
