-- OpenResty / ngx. The bundled luacheck `ngx` standard already knows the API
-- surface; this profile only adds the security meaning.
return {
   name = "openresty",
   sources = {
      -- A blanket over every nginx variable, and not every one of them is
      -- attacker-influenced: $pid, $hostname, $status and $msec are the
      -- server's own. One pattern cannot promise influence for each member it
      -- covers, so the claim made here is the weaker one -- the value is
      -- influenced, not proven attacker data -- which is what the LuCI
      -- dispatcher entry point claims about data inferred rather than read.
      {pattern = "ngx.var.*", id = "ngx.var", name = "nginx variable", confidence = "medium"},
      {pattern = "ngx.req.get_uri_arg", id = "ngx.req.get_uri_arg",
         name = "request query argument", confidence = "certain"},
      {pattern = "ngx.req.get_uri_arg.*", id = "ngx.req.get_uri_arg",
         name = "request query argument", confidence = "certain"},
      -- The plural getters are different functions from the singular ones and
      -- were undeclared, so the documented idiom -- read the whole args table,
      -- then take a column -- matched no source at all. The confidence is the
      -- singular form's for the singular form's reason: it reads the request.
      {pattern = "ngx.req.get_uri_args", id = "ngx.req.get_uri_args",
         name = "request query argument table", confidence = "certain"},
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
      {pattern = "ngx.re.find", code = "728", kind = "pattern", arg = {2}},
      {pattern = "ngx.re.gsub", code = "728", kind = "pattern", arg = {2}},
      -- CVE-2020-36309 (lua-nginx-module < 0.10.16): the API allows unsafe
      -- characters in an argument used to mutate a URI or a request or response
      -- header. Which message the bytes land in is what differs:
      --   response side - ngx.resp.set_header and ngx.redirect write what the
      --     client parses, so a CRLF splits one response into two.
      --   request side - ngx.req.set_header, ngx.req.set_uri and
      --     ngx.req.set_uri_args rewrite the request this handler forwards, so
      --     the CRLF lands on the upstream request, not on the response.
      -- Same defect, same fix: the value must not reach the message unescaped.
      {pattern = "ngx.resp.set_header", code = "730", kind = "header",
         arg = {2}, taint_code = "730", taint_only = true},
      {pattern = "ngx.req.set_header", code = "730", kind = "header",
         arg = {2}, taint_code = "730", taint_only = true},
      {pattern = "ngx.req.set_uri", code = "730", kind = "header",
         arg = {1}, taint_code = "730", taint_only = true},
      {pattern = "ngx.req.set_uri_args", code = "730", kind = "header",
         arg = {1}, taint_code = "730", taint_only = true},
      -- ngx.redirect writes a Location header, so it is response side. It used
      -- to be declared as a search-pattern sink: a tainted target was reported
      -- as 728/CWE-1333 when the argument was merely non-constant, and as
      -- 709/CWE-78 command execution when it was tainted. It runs no command.
      {pattern = "ngx.redirect", code = "730", kind = "header",
         arg = {1}, taint_code = "730", taint_only = true},
      -- CVE-2020-11724 (OpenResty < 1.15.8.4, patched in 9ab38e8). The fix stops
      -- the subrequest from inheriting the parent's Content-Length and crafts
      -- its own, so before it a capture could carry a Content-Length and a
      -- Transfer-Encoding that an upstream proxy and nginx disagreed about. The
      -- second argument is that options table, and a tainted body or header in
      -- it is the caller reaching that framing.
      {pattern = "ngx.location.capture", code = "731", kind = "subrequest",
         arg = {2}, taint_code = "731", taint_only = true},
      -- ngx.header[k] = v is an ASSIGNMENT to an index target, so no call sink
      -- above can see it: a call pattern is matched in callee position and there
      -- is no callee. It is the same defect as ngx.resp.set_header -- the value
      -- reaches the response header message and a CRLF in it splits the response
      -- (CVE-2020-36309) -- so it is the same code rather than a second number
      -- for one meaning, because someone filtering on 730 must see both
      -- spellings. What is new is the position, not the risk; `kind = "assign"`
      -- is what tells the engine to match a target instead of a callee, and
      -- `arg = {1}` here means the first right-hand side, not the first argument.
      --
      -- The pattern matches the TARGET's base (`ngx.header`), not the whole
      -- target, because the key is not the sink:
      --
      --   ngx.header[tainted_key] = "fixed"
      --
      -- is the attacker choosing WHICH header is written while the program still
      -- chooses the bytes in it. That is header selection, not CWE-93 header
      -- injection, so it is deliberately out of scope and reported as nothing.
      -- It is written down rather than left undefined (see docs/rules/730.md)
      -- because it leaves no injection surface open on its own: where the value
      -- is tainted too, the value position below still fires and covers the CRLF.
      {pattern = "ngx.header", code = "730", kind = "assign",
         arg = {1}, taint_code = "730", taint_only = true},
   },
   propagators = {
      {pattern = "ngx.re.gsub", arg = {1}},
      {pattern = "ngx.decode_args", arg = {1}},
   },
   sanitizers = {shell = {}, dyncode = {}, path = {}},
}
