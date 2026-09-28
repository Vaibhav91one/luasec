-- A LuCI controller. `module(..., package.seeall)` puts the dispatcher in scope,
-- so a bare `entry` and `call` are `luci.dispatcher.entry` and `.call`, and
-- `call("action_x")` names a function in this file that the web server runs.
module("luci.controller.example", package.seeall)

function index()
   entry({"admin", "system", "example", "run"}, call("action_run"), nil, 1).leaf = true

   local page = node("example", "reload")
   page.target = call("action_reload")

   -- A template target, and an action with no sink: neither one is a risk.
   entry({"admin", "system", "example", "about"}, template("example/about"), "About", 2)
   entry({"admin", "system", "example", "status"}, call("action_status"), nil, 3)
end

function action_run(command)
   luci.sys.call(command)
end

function action_reload()
   os.execute("/etc/init.d/example restart")
end

function action_status()
   return {uptime = luci.sys.uptime()}
end
