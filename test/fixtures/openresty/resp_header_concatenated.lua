-- The realistic shape: the CRLF arrives through a request header and is
-- concatenated into the value that is written out.
local client = ngx.req.get_headers()["x-client"]
ngx.resp.set_header("X-Echo", "client=" .. client)