gui = {}
gui.net = {}

function gui.net:set(cfg)
   os.execute("set " .. cfg.name)
end
