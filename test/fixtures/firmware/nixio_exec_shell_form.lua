-- The bug, verbatim: a request parameter handed to a shell through the
-- canonical OpenWrt form, where the command is the THIRD argument. The
-- registry declared only the first, so this file reported nothing at all and
-- scored 100/100 (good).
--
-- The parameter is read at the call site rather than passed into a handler
-- because the flow this fixture is about is which ARGUMENT of nixio.exec
-- carries the command. The handler shape is exercised by the 724 specs in
-- firmware_spec.lua.
nixio.exec("/bin/sh", "-c", luci.http.formvalue("cmd"))
