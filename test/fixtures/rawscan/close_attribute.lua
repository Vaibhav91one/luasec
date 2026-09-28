-- <close> is a Lua 5.4 attribute. The parser behind this tool reads it, so this
-- file is not unparseable - which is exactly why a dialect mismatch has to be a
-- different finding from a construct the parser cannot handle.
local handle <close> = io.open("/etc/shadow", "r")
return handle
