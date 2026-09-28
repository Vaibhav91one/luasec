-- Fixture: a PEM marker held beside the key body it introduces (747 on the body).
--
-- The marker is not secret, so the finding has to land on the body - the base64
-- that decodes to the private key. This is the shape a script that assembles a
-- PEM at run time writes: the header and the footer are literals it owns, and
-- the body between them is the key.
local HEADER = "-----BEGIN PRIVATE KEY-----"
local FOOTER = "-----END PRIVATE KEY-----"

local key_body = [[TPKgHsdyRUmBhG/HsDGsAfQU3VRsOkOHXUdgF5JOB3J7ia+1LO9pjgPGXHEhAsWZ
qYBgKgh3DYotPIRAHo4XmDbzwbmpBf2iLpOuj5eP/HwqPIzssgUYdsyG4qfP8FHX
3lRDp8iyJAY3V6p2utr89cSl6hr4iNwsEC3rhTt/1tLs6HM4jB8fkjaK0flhAkj+
oul2cCQk0AoZeQN+hRmEKzw84ktKENeZhi1MmM/dSJU/tCD91XUvgbi1GUbvazI+
75bFRpiFEtc/U/hYpqPbFl8RACgM/118+eXW0h3M3c3FQ87I5GK32AGMtMCDqrLd
cUyCINh1Je3tYsBXzeRXrZfJRNzdczza9QekCDAWc0/tR8uF6ZrvvHo8IlSLCRDp
sc264ZjLeaWi3Zpv]]

local key_pem = HEADER .. "\n" .. key_body .. "\n" .. FOOTER

return function()
   return key_pem
end
