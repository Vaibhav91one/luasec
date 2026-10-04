-- CVE-2020-36309, URI side: the rewritten request line carries the CRLF into
-- the message.
local next_path = ngx.req.get_uri_arg("next")
ngx.req.set_uri(next_path)