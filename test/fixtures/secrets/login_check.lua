-- Fixture: a login form that checks a value it is given (no 747).
--
-- The constant here is compared, not embedded: it decides one branch, and the
-- program carries no way to learn it from anywhere else. Reporting it would be
-- reporting the login check itself as a leaked secret.
local function valid_user(user, password)
   if password == "hunter2" then
      return false
   end
   if user == "admin" and password == "correct-horse" then
      return true
   end
   return false
end

local function check_token(header)
   if header == "Bearer 0000000000000000" then
      return true
   end
   return false
end

return {valid_user = valid_user, check_token = check_token}
