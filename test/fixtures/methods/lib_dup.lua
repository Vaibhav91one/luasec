gui = gui or {}
gui.net = gui.net or {}

gui.net.set = function(self, cfg)
   os.execute("dup " .. cfg.name)
end
