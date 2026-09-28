-- A long string opened here never closes, so every byte from line 3 to the end
-- of the file is string content. An `os.execute` sits in that tail: a scan that
-- reported it would be reporting text, and a scan that said nothing would be
-- reporting a file it never read.
local note = [[
   os.execute("rm -rf /")
   io.popen("sh")
