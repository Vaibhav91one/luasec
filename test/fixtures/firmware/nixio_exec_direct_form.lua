-- The form that was already covered and must keep being covered: the command
-- is the first argument, so `arg = {1}` was right for this call and only for
-- this call.
nixio.exec(luci.http.formvalue("cmd"))
