-- CVE-2020-36309: a request parameter copied into a response header.
local name = ngx.req.get_uri_arg("name")
ngx.resp.set_header("X-Echo", name)