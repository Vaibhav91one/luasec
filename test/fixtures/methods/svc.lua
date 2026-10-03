local M = {}

function M:run(cfg)
   os.execute("run " .. cfg.name)
end

M.go = function(self, cfg)
   os.execute("go " .. cfg.name)
end

function M:id(value)
   return value
end

return M
