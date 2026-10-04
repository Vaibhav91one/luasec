-- A constant assigned into ngx.header is what almost every real handler writes,
-- so it is the same shape as the constant call in header_writes_literal.lua. Only
-- proven request data is a finding.
local content_type = "application/json"
ngx.header["Content-Type"] = content_type

ngx.header["X-Powered-By"] = "OpenResty"