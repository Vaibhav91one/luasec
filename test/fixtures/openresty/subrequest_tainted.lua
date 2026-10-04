-- CVE-2020-11724: a subrequest whose body is built from request data lets the
-- caller frame the upstream request.
local payload = ngx.req.get_post_args()
ngx.location.capture("/api/forward", {method = "POST", body = payload})