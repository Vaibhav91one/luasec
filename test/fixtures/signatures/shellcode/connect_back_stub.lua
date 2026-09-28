-- Fixture: machine code assembled with string.char (746).
--
-- xor eax,eax; push rax; push "//sh"; mov ebx,esp; xor ecx,ecx; xor edx,edx;
-- mov al,11; int 0x80 - the connect-back stub itself, not a description of
-- one. The prose above is what makes the shape recognisable; the bytes are
-- what the detector reads.
local STUB = string.char(
   31, 192,          -- xor eax, eax
   50,               -- push rax
   104, 47, 47, 115, 104,   -- push "//sh"
   139, 227,          -- mov ebx, esp
   31, 201,          -- xor ecx, ecx
   31, 210,          -- xor edx, edx
   176, 11,          -- mov al, 11
   205, 128)         -- int 0x80

local FRAME = string.char(
   55, 48, 131, 247,  -- push rbp; sub rsp, 0xf7
   55, 48, 131, 236,  -- push rbp; sub rsp, 0xec
   55, 48, 131, 85)   -- push rbp; sub rsp, 0x55

return {STUB, FRAME}
