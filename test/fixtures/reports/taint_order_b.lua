-- Same two tainted sinks as taint_order.lua, named so that the alphabetical
-- order of the files disagrees with the order of the findings inside them.
-- A report that sorted by file name alone would emit this file's 709s first.
local tainted = http.formvalue("a")

local other = os.getenv("B")

io.popen("traceroute " .. other)
os.execute("ping -c1 " .. tainted)

return {}
