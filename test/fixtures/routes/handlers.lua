function doLogin(req)
   return req.user
end

function doSet(req)
   os.execute("set " .. req.value)
end
