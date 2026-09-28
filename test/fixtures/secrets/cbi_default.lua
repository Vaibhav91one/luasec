-- The LuCI form: the field's name is the label the builder was given, and the
-- value is assigned to .default / .value afterwards.
local option = s.option("Password", "telnet password")
option.default = "t3ln3tPassw0rd-99"

local value = s:value("Token", "api token")
value.value = "0123456789abcdef0123456789"

local entry = s.entry(m.section, "Key", "wifi key")
entry.value = "abcdef0123456789abcdef01"
