from pwn import *

libc_base = 0x738b33800000

libc = ELF("./libc.so.6", checksec=False)
system_addr = libc_base + libc.sym["system"]

print("libc_base =", hex(libc_base))
print("system    =", hex(system_addr))
