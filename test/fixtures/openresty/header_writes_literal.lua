-- A header value that is a constant local is what almost every real handler
-- writes. Only proven request data is a finding.
local content_type = "application/json"
ngx.resp.set_header("Content-Type", content_type)

local upstream = "/api/v1/status"
ngx.location.capture(upstream, {method = "GET"})