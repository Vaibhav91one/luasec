gui = gui or {}
gui.net = {}
gui.net.trace = {}

function gui.net.trace.set(cfg)
   util.runShellCmd("traceroute " .. cfg.host)
   return "OK", "STATUS_OK"
end
