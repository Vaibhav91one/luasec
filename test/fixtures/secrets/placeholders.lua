-- Fixture: credential-named names holding values that are not secrets (no 747).
local form = {
   password = "type it here",
   token = "your-token-goes-in-here",
   auth = "basic",
   key = "",
   api_key = "CHANGEME",
   private_key = "path/to/key.pem",
   secret = "none",
}

local function describe_the_field(kind)
   return kind
end

return {form = form, describe_the_field = describe_the_field}
