-- An installer that writes a service script and then rewrites the file it just
-- wrote, truncating whatever the first pass put there.
local function install(body)
   local first = io.open("/etc/init.d/tunnel", "w")
   first:write(body)
   first:close()
   local second = io.open("/etc/init.d/tunnel", "w")
   second:write(body .. " # patched")
   second:close()
end

return install
