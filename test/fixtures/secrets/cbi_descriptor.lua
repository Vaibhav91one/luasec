-- A CBI control has one field that holds the user's value and about a dozen
-- that describe the field. All of the descriptors are short strings, and
-- reporting one as a hardcoded credential is the mistake this rule made on
-- real firmware: public_key.datatype = "and(base64,rangelength(44,44))".
local peers = s:tab("peers", "Peers")

local public_key = peers:option(Value, "public_key", "Public Key")
public_key.datatype = "and(base64,rangelength(44,44))"
public_key.optional = false
public_key.rmempty = true

local preshared_key = peers:option(Value, "preshared_key", "Preshared Key")
preshared_key.password = true
preshared_key.datatype = "and(base64,rangelength(44,44))"
preshared_key.depends("proto", "wireguard")
