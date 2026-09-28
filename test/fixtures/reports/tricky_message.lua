-- Fixture: a finding whose message carries text that is awkward in every syntax
-- a report might be written in - a double quote, a backslash, a tab, a newline
-- and non-ASCII bytes. The label the secret is bound to is the only part of this
-- finding that comes from the analyzed file, so it is where a reporter can be
-- made to lie about where the text ends.
local cfg = {}

cfg["api\"key\twith\\backslash\nnewline \xc3\xa9 \xe6\x97\xa5\xe6\x9c\xac"] = "hunter2hunter2"

return cfg
