-- Fixture: a loader fed values the program never decoded (no 741, no 743).
local script = "return 1"

local function from_argument(source)
   return loadstring(source)
end

local function from_concatenation(part)
   return loadstring("return " .. part)
end

local function from_a_field(config)
   return loadstring(config.script)
end

local function from_a_request()
   return loadstring(http.formvalue("code"))
end

return {
   from_argument = from_argument,
   from_concatenation = from_concatenation,
   from_a_field = from_a_field,
   from_a_request = from_a_request,
   literal = script,
}
