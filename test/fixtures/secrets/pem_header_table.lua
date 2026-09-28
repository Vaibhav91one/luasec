-- Fixture: the header lines a script writes around a PEM it builds at run time
-- (no 747).
--
-- The shape is luci-lib-px5g's der2pem: a table of `-----BEGIN ...-----` lines
-- plus a table of the matching END lines, and the key material computed by
-- nixio.bin.b64encode. Nothing here is a secret; the marker is not a key.
local nixio = require "nixio"

local preamble = {
   key = "-----BEGIN RSA PRIVATE KEY-----",
   cert = "-----BEGIN CERTIFICATE-----",
   request = "-----BEGIN CERTIFICATE REQUEST-----",
}

local postamble = {
   key = "-----END RSA PRIVATE KEY-----",
   cert = "-----END CERTIFICATE-----",
}

function der2pem(data, kind)
   local out = {preamble[kind]}
   for index = 1, #data, 64 do
      out[#out + 1] = nixio.bin.b64encode(data:sub(index, index + 63))
   end
   out[#out + 1] = postamble[kind]
   return table.concat(out, "\n")
end

return der2pem
