-- Fixture: a finding whose message text is markup. A report that pastes a
-- finding's message into a page without escaping turns a scanned file into
-- script that runs in the reviewer's browser, which is the one thing a security
-- report must never do. The label is the only part of this finding that comes
-- from the analyzed file, so it is the part a reporter can be made to lie about.
local cfg = {}

cfg["<script>alert(1)</script>api_key"] = "hunter2hunter2"

return cfg
