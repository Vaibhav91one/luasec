-- Both spellings of the same defect in one handler: the deprecated call form
-- from #227 and the modern assignment form. The engine matches a callee for one
-- and a target for the other, so this is where a change to either would show.
local token = ngx.req.get_uri_arg("token")
ngx.resp.set_header("X-Call", token)
ngx.header["X-Assign"] = token