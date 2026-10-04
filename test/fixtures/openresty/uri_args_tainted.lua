-- The rewritten query string is part of the request line, so a CRLF in it is
-- the same write as a rewritten path.
local page = ngx.req.get_uri_arg("page")
ngx.req.set_uri_args("page=" .. page)