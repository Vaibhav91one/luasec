-- A key written straight into the flash config. No variable, no table, no
-- name on the value: only the key argument says what it is.
uci.set("wireless", "default", "key", "5up3r53cr3tk3y0123456789")
local cursor = uci.cursor()
cursor:set("system", "root", "password", "R00tPassw0rd-2024")
