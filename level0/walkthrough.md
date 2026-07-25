# Level 0

First, identify the binary and its permissions:

```
$ file level0
level0: ELF 32-bit LSB executable, Intel 80386, ... dynamically linked

$ ls -l level0
-rwsr-x---+ 1 level1 users 747441 ... level0
```

The `s` in `-rwsr-x---` is the SUID bit, and the owner is level1.

> **SUID binary:** the program runs with the file owner's privileges, not the caller's. This one is owned by level1, so a shell it spawns runs as level1 and can read `/home/user/level1/.pass`.

## Analysis

Disassemble `main` in GDB (assembly and command reference: [GDB guide](../knowledge_base/gdb_guide.md)):

```
(gdb) disas main
```

The relevant part:

```asm
call   <atoi>                ; atoi(argv[1])
cmp    $0x1a7,%eax           ; compare result to 0x1a7
jne    0x8048f58 <main+152>  ; not equal -> fail branch
```

`main` converts `argv[1]` to an int and checks if it equals `0x1a7`.

```
(gdb) p/d 0x1a7
$1 = 423
```

If it matches, the success branch drops privileges to level1 and runs a shell:

```asm
call   <setresgid>
call   <setresuid>
call   <execv>     ; execv("/bin/sh", ...)
```

Otherwise it just prints `No !`.

## Exploit

Pass `423` as the argument:

```
$ ./level0 423
$ cat /home/user/level1/.pass
1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
```

Flag: `1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a`
