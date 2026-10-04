-- The key and the value are different questions. A tainted key chooses WHICH
-- header is written while the program still chooses the value; a tainted value
-- is what reaches the HTTP message. This pins the decision that the key
-- position is not a sink: see the note on the `assign` kind in the openresty
-- profile and docs/rules/730.md.
local name = ngx.req.get_uri_arg("name")
ngx.header[name] = "fixed"