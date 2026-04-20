# Heap Overflow

## Stack vs Heap

| | Stack | Heap |
|---|---|---|
| Allocation | Automatic (local variables) | Manual (malloc/new) |
| Grows | Downward (high → low) | Upward (low → high) |
| Layout | Predictable (frame-based) | Dynamic (chunks with metadata) |
| Overflow target | Return address | Heap metadata, function pointers, vtables |

```c
char stack_buf[64];                // on the stack
char *heap_buf = malloc(64);       // on the heap
```

## The overflow

Same concept as stack overflow: writing more data than a buffer can hold. But on the heap, there's no return address to overwrite. Instead, the targets are:

1. **Adjacent heap data**: overwrite the next allocation's content
2. **Heap metadata**: corrupt malloc's internal bookkeeping
3. **Function pointers**: overwrite a function pointer stored on the heap
4. **C++ vtables**: overwrite the virtual method table pointer

## Heap layout

When you malloc two buffers:

```c
char *a = malloc(64);
char *b = malloc(64);
```

Memory layout:
```
┌──────────────┐
│ chunk header  │  ← malloc metadata for a (size, flags)
├──────────────┤
│ a's data     │  ← 64 bytes you can use
│ (64 bytes)   │
├──────────────┤
│ chunk header  │  ← malloc metadata for b
├──────────────┤
│ b's data     │  ← 64 bytes you can use
│ (64 bytes)   │
└──────────────┘
```

If you overflow `a`, you write into `b`'s chunk header and data.

## Exploit pattern 1: Overwrite adjacent data

```c
char *a = malloc(64);
char *b = malloc(64);

strcpy(a, user_input);     // overflow a → overwrites b's content
strcpy(b, "safe string");  // b already corrupted

if (strcmp(b, "admin") == 0) {
    grant_access();         // we overwrote b with "admin"
}
```

## Exploit pattern 2: Overwrite function pointers

```c
typedef struct {
    char name[64];
    void (*callback)(void);
} Entry;

Entry *e = malloc(sizeof(Entry));
e->callback = safe_function;
strcpy(e->name, user_input);    // overflow name → overwrites callback
e->callback();                   // calls whatever we wrote
```

## Exploit pattern 3: C++ vtable overwrite

In C++, objects with virtual methods have a vtable pointer as the first field:

```
Object on heap:
┌──────────────┐
│ vtable ptr   │  ← points to table of virtual method addresses
├──────────────┤
│ member data  │
│ ...          │
└──────────────┘
```

If you overflow into the vtable pointer, you can redirect all virtual method calls to your own addresses.

```cpp
class A {
    char buf[64];
    virtual void action() { /* safe */ }
};

class B {
    virtual void action() { system("/bin/sh"); }
};

A *obj = new A();
strcpy(obj->buf, user_input);    // overflow buf → overwrite vtable ptr
obj->action();                    // calls our redirected function
```

## Key differences from stack overflow

- No return address on the heap; can't directly hijack control flow
- Need a function pointer, vtable, or other indirect call nearby
- Heap layout depends on allocation order and sizes
- Requires understanding of how malloc organizes chunks

## How to analyze in GDB

```bash
# Set breakpoint after mallocs
(gdb) b *0x0804xxxx

# Examine heap allocations
(gdb) x/40x <address>

# See the distance between two allocations
(gdb) p/x (long)b - (long)a

# After overflow, check what got corrupted
(gdb) x/s b
```

## When to use

- Program uses malloc/new and copies user input without size checks
- Two or more allocations are close together on the heap
- A function pointer or vtable is stored on the heap
- strcpy, memcpy, or similar is used without bounds checking
