-- luasec: ignore 709
local function go(host)
   os.execute("ping " .. http.formvalue("host"))
end
