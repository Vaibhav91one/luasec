-- OpenResty / ngx. The bundled luacheck `ngx` standard already knows the API
-- surface; this profile only adds the security meaning.
return {
   name = "openresty",
   sources = {
      {pattern = "ngx.var.*", id = "ngx.var", name = "nginx variable", confidence = "high"},
      {pattern = "ngx.req.get_uri_arg", id = "ngx.req.get_uri_arg",
         name = "request query argument", confidence = "certain"},
      {pattern = "ngx.req.get_uri_arg.*", id = "ngx.req.get_uri_arg",
         name = "request query argument", confidence = "certain"},
      {pattern = "ngx.req.get_post_args", id = "ngx.req.get_post_args",
         name = "request body", confidence = "certain"},
      {pattern = "ngx.req.get_headers", id = "ngx.req.get_headers",
         name = "request header", confidence = "certain"},
      {pattern = "ngx.req.get_body_data", id = "ngx.req.get_body_data",
         name = "request body", confidence = "certain"},
   },
   sinks = {
      {pattern = "ngx.exec", code = "701", kind = "exec", arg = {1}},
      {pattern = "ngx.pty.spawn", code = "701", kind = "exec", arg = {1}},
      {pattern = "ngx.redirect", code = "728", kind = "pattern", arg = {1}},
      {pattern = "ngx.re.find", code = "728", kind = "pattern", arg = {2}},
      {pattern = "ngx.re.gsub", code = "728", kind = "pattern", arg = {2}},
   },
   propagators = {
      {pattern = "ngx.re.gsub", arg = {1}},
      {pattern = "ngx.decode_args", arg = {1}},
   },
   sanitizers = {shell = {}, dyncode = {}, path = {}},
}
