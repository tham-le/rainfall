# Use-After-Free

A use-after-free (UAF) happens when:
1. Memory is allocated (malloc)
2. Memory is freed (free)
3. The program still uses the freed pointer

After free(), the memory goes back to malloc's pool. A new malloc() of the same size will likely return that same chunk. If the old pointer is still used, it now reads/writes the new allocation's data.

## Simple example

```c
char *a = malloc(64);
strcpy(a, "hello");

free(a);                    // a is freed but pointer still exists

char *b = malloc(64);       // b gets the same memory as a
strcpy(b, "malicious");

printf("%s\n", a);          // prints "malicious": a and b point to same memory
```

## Why is it dangerous?

If the freed memory contained a function pointer, and the new allocation overwrites it:

```c
struct User {
    char name[32];
    void (*auth)(void);
};

struct User *admin = malloc(sizeof(struct User));
admin->auth = admin_check;

free(admin);                        // freed but admin pointer still used

char *data = malloc(sizeof(struct User));  // gets same memory
memcpy(data, user_input, 40);       // overwrite where auth was

admin->auth();                       // calls whatever we put at offset 32
```

## How malloc reuses memory

malloc keeps a list of freed chunks (the "free list"). When you malloc again with the same size, it gives you the most recently freed chunk:

```
malloc(64) → address 0x0804a008
free(0x0804a008) → goes to free list
malloc(64) → returns 0x0804a008 again (same address!)
```

This is why the attack works: you control what gets written to the recycled memory.

## Exploit pattern

1. Object A is allocated with function pointer/vtable
2. Object A is freed
3. Attacker triggers allocation of same size
4. Attacker controls the content of the new allocation
5. Program uses old pointer to A → reads attacker's data
6. Function call through old pointer → executes attacker's code

## How to spot it

In the source code / decompilation, look for:
- `free(ptr)` followed by later use of `ptr`
- No `ptr = NULL` after `free(ptr)`
- Multiple code paths where one frees and another uses
- C++ `delete` followed by use of the object

## How to analyze in GDB

```bash
# Watch allocations
(gdb) b malloc
(gdb) b free

# After each, check what address is returned/freed
(gdb) finish
(gdb) p/x $eax           # return value of malloc

# Compare addresses: if they match after free+malloc, you have reuse
```

## When to use

- Program frees memory then keeps using the pointer
- You can trigger a new allocation of the same size between free and use
- The freed object contained function pointers, vtable, or important data
