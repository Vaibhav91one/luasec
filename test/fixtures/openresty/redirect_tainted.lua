-- ngx.redirect writes a Location header; it runs no command.
local target = ngx.req.get_uri_arg("next")
ngx.redirect(target)