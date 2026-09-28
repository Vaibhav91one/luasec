-- A LuCI CBI model. The framework calls the hooks below when the form is
-- submitted, and it gets the map because the model file hands it back.
m = Map("example", translate("Example"))

m.on_after_commit = function()
   luci.sys.call("/etc/init.d/example restart")
end

m.on_after_save = function()
   os.execute("/usr/bin/example --reload")
end

-- A method, but not a hook: the framework calls it for a value it renders, and
-- it executes nothing.
m.read = function(self, section)
   return {name = section}
end

return m
