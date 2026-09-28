-- Fixture: a private key block as a literal, under a name that says nothing (747).
local M = {}

function M.signer()
   return [[-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIBpVY2hhbmdlIG9uZSBsaW5lIG9mIGJhc2U2NCBieXRlcyBmb3Ig
dGhlIHRlc3QsIG5vdCBhIHJlYWwga2V5IGF0IGFsbCwgZG8gbm90IHB1Ymxpc2g=
-----END EC PRIVATE KEY-----]]
end

return M
