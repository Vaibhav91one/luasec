-- A `-- luasec:` directive whose pattern is not a pattern. The operator's typo
-- used to be handed to string.match, which raised "malformed pattern" and
-- killed the scan: breaking the DIRECTIVE parser gets a clean report exactly as
-- breaking the parser does, and this is the tool's own stated threat model.
-- luasec: ignore [708
os.execute(cmd)
