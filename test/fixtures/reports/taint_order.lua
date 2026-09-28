-- Two findings in one file, deliberately emitted out of order, so the report's
-- own ordering is what decides the byte output rather than the order the
-- engine happened to produce or the order the files were named on the command
-- line. The sink is on the earlier line of the file.
local first = http.formvalue("a")

local second = os.getenv("B")

os.execute("ping -c1 " .. first)
io.popen("traceroute " .. second)

return {}
