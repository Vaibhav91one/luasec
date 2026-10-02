routes = {
   ["Set"] = {["methodHandler"] = doSet},
}

local req = {value = "fixed"}
routes[cgi["op"]]["methodHandler"](req)
