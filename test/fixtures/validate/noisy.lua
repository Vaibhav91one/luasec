-- Prints to standard output, then does something harmless. The validator has to
-- keep those bytes out of its own report.
print("PAYLOAD-PRINTED-THIS")
io.write("PAYLOAD-WROTE-THIS\n")
local total = 0
for i = 1, 10 do total = total + i end
return total
