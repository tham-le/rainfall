# GOT Overwrite

GOT = Global Offset Table. It's a table in memory that stores the real addresses of dynamically linked functions (like printf, system, puts).

When your program calls `printf()`, it doesn't jump directly to printf's code. Instead:

```
Your code → PLT (Procedure Linkage Table) → GOT → actual printf() in libc
```

The first time printf is called:
1. Jump to PLT entry for printf
2. PLT reads GOT entry (initially points back to PLT resolver)
3. Resolver finds printf in libc, writes real address into GOT
4. Jumps to printf

Every subsequent call:
1. Jump to PLT entry for printf
2. PLT reads GOT entry (now has real address)
3. Jump directly to printf in libc

## Why is it exploitable?

If RELRO is disabled (No RELRO), the GOT is writable. If you can write to arbitrary memory (e.g., via format string %n), you can overwrite a GOT entry to point to a different function.

Example: overwrite `puts@GOT` with `system()`'s address. Next time the program calls `puts(user_input)`, it actually calls `system(user_input)`.

## How to find GOT addresses

### In GDB:
```
(gdb) info functions @plt
(gdb) x/i 0x08048340              # examine PLT entry
(gdb) x/x 0x08049784              # read GOT entry
```

### With objdump:
```bash
objdump -R binary                  # shows relocation entries (GOT addresses)
objdump -d binary | grep @plt     # shows PLT entries
```

### With readelf:
```bash
readelf -r binary                  # shows relocations
```

## Step by step

### 1. Find the vulnerability

Usually a format string bug: `printf(user_input)`

### 2. Find the GOT address of a function to overwrite

Choose a function that's called AFTER the format string vulnerability, and ideally one that takes user input as argument.

Good targets:
- `puts(buffer)` → overwrite with system() → calls system(buffer)
- `exit()` → overwrite with shellcode address or another function

```bash
objdump -R binary | grep puts
# 0x08049784  puts
```

### 3. Find the address to write (system, shellcode, etc.)

```
(gdb) p system
0xb7e6b060
```

### 4. Overwrite GOT entry using format string

```bash
python -c "
import struct
got = 0x08049784           # puts@GOT
target = 0xb7e6b060        # system() address

# Build format string to write target into got
# Using %hn to write 2 bytes at a time
payload = struct.pack('I', got)        # low 2 bytes destination
payload += struct.pack('I', got + 2)   # high 2 bytes destination
# ... add appropriate %Nx and %hn specifiers
" | ./binary
```

### 5. Trigger the overwritten function

When the program calls `puts(buffer)`, it now calls `system(buffer)`. If buffer contains "/bin/sh", you get a shell.

## Example scenario

```c
char buf[100];
fgets(buf, 100, stdin);
printf(buf);              // format string vulnerability: write to GOT here
puts("Done");             // this now calls system("Done") if we overwrote puts@GOT
```

Better scenario:
```c
char buf[100];
fgets(buf, 100, stdin);
printf(buf);              // overwrite exit@GOT with some useful address
exit(0);                  // now jumps to our target
```

## GOT vs direct return address overwrite

| | Return address overwrite | GOT overwrite |
|---|---|---|
| Requires | Buffer overflow | Format string (or arbitrary write) |
| Overwrites | Stack (return address) | GOT (function pointer in .got.plt) |
| Trigger | Function returns (ret) | Function is called via PLT |
| Protection | Stack canary | RELRO |

## When to use

- RELRO is disabled (GOT is writable)
- You have a format string vulnerability (or other arbitrary write primitive)
- You can't overflow the return address (e.g., buffer is too controlled)
