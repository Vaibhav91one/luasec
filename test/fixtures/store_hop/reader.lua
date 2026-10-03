function apply_hostname()
   local name = db.getAttribute("system", "_ROWID_", "1", "hostname")
   os.execute("hostname " .. name)
end
