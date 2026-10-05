-- `nixio.execp(cmd, ...)` is nixio's "find the executable on PATH" form of
-- exec. It was not declared at all, so a request parameter reaching it
-- reported nothing and scored 100/100 (good).
--
-- The parameter is read at the call site rather than passed into a handler
-- because the flow this fixture is about is which ARGUMENT of nixio.execp
-- carries the command. The handler shape is exercised by the 724 specs in
-- firmware_spec.lua.
nixio.execp(luci.http.formvalue("cmd"))
