-- Both positions tainted: the key chooses the header name and the value is what
-- reaches the message. The value position is the sink, so this fires -- which is
-- why a tainted key needs no code of its own to leave the injection surface
-- covered.
local name = ngx.req.get_uri_arg("name")
ngx.header[name] = name