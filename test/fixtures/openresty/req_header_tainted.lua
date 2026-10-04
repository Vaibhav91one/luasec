-- CVE-2020-36309, request side: a reverse proxy handler copies a parameter
-- into a request header, so the CRLF lands on the upstream request.
local name = ngx.req.get_uri_arg("name")
ngx.req.set_header("X-Forwarded-For", name)