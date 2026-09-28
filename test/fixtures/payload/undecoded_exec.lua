-- Fixture: a command sink fed values the program never decoded (no 743).
local function from_argument(command)
   os.execute(command)
end

local function from_a_field(config)
   os.execute(config.command)
end

local function from_a_request()
   os.execute("ping -c1 " .. http.formvalue("host"))
end

local function fixed()
   os.execute("/sbin/reboot")
end

return {
   from_argument = from_argument,
   from_a_field = from_a_field,
   from_a_request = from_a_request,
   fixed = fixed,
}
