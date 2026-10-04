-- The modern idiom for writing a response header. This is an assignment to an
-- index target, not a call, so no call-pattern sink can match it -- and it is
-- the form upstream lua-resty-jwt's own example uses.
local token = ngx.req.get_uri_arg("token")
ngx.header["Set-Cookie"] = token