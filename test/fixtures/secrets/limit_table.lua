-- Fixture: a table of limits where "key" names a field, not a secret (no 747).
local LIMITS = {
   {key = "timeout_ms", default = 2000, high = 3600000},
   {key = "max_memory_kb", default = 65536, low = 1024},
   {key = "max_load_depth", default = 32},
   {key = "max_source_bytes", default = 262144},
}

return LIMITS
