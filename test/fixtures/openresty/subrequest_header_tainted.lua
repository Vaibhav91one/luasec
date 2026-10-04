-- CVE-2020-11724, header variant: a subrequest header built from request data.
local host = ngx.req.get_uri_arg("host")
ngx.location.capture("/api", {headers = {["X-Forwarded-Host"] = host}})