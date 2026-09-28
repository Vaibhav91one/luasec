-- A file the parser rejects, and a real command execution sink in it.
-- The missing close paren is the whole attack: break the parse and the file
-- used to come back as a single "could not parse" note.
local function go(cmd)
   os.execute(cmd
