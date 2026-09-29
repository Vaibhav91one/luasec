-- Fixture: a request parameter handed to a helper in a required module,
-- where the helper's return value reaches os.execute. Three call shapes:
-- a local bound to the module field, an inline require call, and a value
-- bound through the module field before use.
local m = require "idmod"

local function via_local(host)
   local v = m.id(http.formvalue(host))
   os.execute(v)
end

local function via_inline(host)
   os.execute(require "idmod".id(http.formvalue(host)))
end

local function via_temp(host)
   os.execute(m.id(http.formvalue(host)))
end

-- A constant argument through the identity field must not be reported as 709.
local function constant_call()
   os.execute(m.id("ls"))
end

-- A quoting helper in the module must not be reported as 709, and must not
-- raise a 712, just like the same-file quoting-field spec.
local function quoting_field(host)
   os.execute("echo " .. m.q(http.formvalue(host)))
end

return {via_local, via_inline, via_temp, constant_call, quoting_field}
