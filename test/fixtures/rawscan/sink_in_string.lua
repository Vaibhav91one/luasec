-- Does not parse, and every sink name in it is quoted text.
local banner = "we used to call os.execute here, safely"
local table_ctor = {io.popen = "not a call", loadstring = "nor this"}
local function go(cmd
