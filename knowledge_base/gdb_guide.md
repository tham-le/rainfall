# GDB Guide for Binary Exploitation

## Starting GDB

```bash
gdb ./binary              # open a binary
gdb -q ./binary           # quiet mode (no banner)
```

## Reading x86 Assembly (32-bit)

### Registers

Think of registers as small built-in variables in the CPU:

| Register | Purpose |
|---|---|
| `EAX` | Return value of functions, also used for math |
| `EBX` | General purpose |
| `ECX` | Counter (used in loops) |
| `EDX` | General purpose, also used in division |
| `ESI` | Source pointer (for string operations) |
| `EDI` | Destination pointer (for string operations) |
| `ESP` | Stack pointer, always points to the top of the stack |
| `EBP` | Base pointer, points to the start of the current stack frame |
| `EIP` | Instruction pointer, address of the next instruction to execute |

`EIP` is the most important for exploitation: if you control EIP, you control where the program goes next.

### Common instructions

#### Moving data

| Instruction | Meaning | C equivalent |
|---|---|---|
| `mov eax, 5` | eax = 5 | `int a = 5;` |
| `mov eax, ebx` | eax = ebx | `a = b;` |
| `mov eax, [ebx]` | eax = value at address ebx | `a = *b;` |
| `mov [eax], ebx` | store ebx at address eax | `*a = b;` |

#### LEA: Load Effective Address

`lea` loads an address, not the value at that address:

```asm
lea eax, [esp + 0x10]    ; eax = esp + 16 (an address, not a value)
mov eax, [esp + 0x10]    ; eax = value stored at esp + 16
```

Think of it as: `lea` = "give me the pointer", `mov` with brackets = "give me what's at the pointer".

#### Stack operations

| Instruction | Meaning | What happens |
|---|---|---|
| `push eax` | Put eax on the stack | ESP decreases by 4, value stored at ESP |
| `pop eax` | Take top of stack into eax | Value loaded from ESP, ESP increases by 4 |
| `sub esp, 0x50` | Reserve 0x50 bytes on stack | ESP moves down (stack grows down) |
| `add esp, 0x50` | Free 0x50 bytes on stack | ESP moves up |

#### Arithmetic

| Instruction | Meaning | C equivalent |
|---|---|---|
| `add eax, 5` | eax += 5 | `a += 5;` |
| `sub eax, 5` | eax -= 5 | `a -= 5;` |
| `xor eax, eax` | eax = 0 | `a = 0;` (fastest way to zero a register) |
| `and esp, 0xfffffff0` | Align ESP to 16 bytes | Stack alignment |

#### Comparisons and jumps

```asm
cmp eax, 0x1a7       ; compare eax to 0x1a7 (sets CPU flags)
jne 0x8048f58         ; jump if NOT equal
je  0x8048f58         ; jump if equal
jmp 0x8048f58         ; jump always (unconditional)
```

| Jump | Meaning | When it jumps |
|---|---|---|
| `je` / `jz` | Jump if equal / zero | Values are the same |
| `jne` / `jnz` | Jump if not equal / not zero | Values differ |
| `jg` / `jge` | Jump if greater (than) / greater or equal | Signed comparison |
| `jl` / `jle` | Jump if less (than) / less or equal | Signed comparison |
| `ja` / `jae` | Jump if above / above or equal | Unsigned comparison |
| `jb` / `jbe` | Jump if below / below or equal | Unsigned comparison |

Reading `cmp` + `jne` together:
```asm
cmp eax, 0x1a7       ; if (eax == 0x1a7)
jne 0x8048f58         ;   skip to 0x8048f58 if NOT equal
                      ;   continue here if equal
```

This is an `if` statement:
```c
if (eax != 0x1a7)
    goto 0x8048f58;   // the else branch
// the if-true branch continues here
```

#### Function calls

```asm
call 0x8048340        ; push return address, jump to 0x8048340
ret                   ; pop return address, jump to it
```

`call` does two things:
1. Pushes the address of the next instruction onto the stack (return address)
2. Jumps to the target function

`ret` does the reverse:
1. Pops the address from the top of the stack
2. Jumps to it

This is why overwriting the return address on the stack controls where `ret` goes.

#### Function prologue and epilogue

Every function starts and ends the same way:

```asm
; Prologue: set up stack frame
push ebp              ; save caller's base pointer
mov  ebp, esp         ; set our base pointer to current stack top
sub  esp, 0x50        ; reserve space for local variables

; ... function body ...

; Epilogue: tear down stack frame
leave                 ; same as: mov esp, ebp; pop ebp
ret                   ; return to caller
```

## How to identify function arguments

In 32-bit x86, arguments are passed on the stack. Look for `mov` instructions that put values at `(%esp)`, `0x4(%esp)`, `0x8(%esp)` right before a `call`:

```asm
mov    %eax,(%esp)          ; 1st argument
call   <gets@plt>           ; gets(eax)
```

```asm
movl   $0x8048570,(%esp)    ; 1st argument = string at 0x8048570
movl   $0x1,0x4(%esp)       ; 2nd argument = 1
movl   $0x13,0x8(%esp)      ; 3rd argument = 0x13 (19)
mov    %edx,0xc(%esp)       ; 4th argument = edx (some variable)
call   <fwrite@plt>         ; fwrite(0x8048570, 1, 19, edx)
```

Stack positions for arguments:
| Position | Argument |
|---|---|
| `(%esp)` or `0x0(%esp)` | 1st argument |
| `0x4(%esp)` | 2nd argument |
| `0x8(%esp)` | 3rd argument |
| `0xc(%esp)` | 4th argument |

## How to identify local variables

Local variables live at offsets from ESP (or EBP) within the reserved stack space:

```asm
sub    $0x50,%esp            ; reserve 80 bytes
lea    0x10(%esp),%eax       ; local variable at esp + 16 (a buffer)
movl   $0x0,0x1c(%esp)       ; local variable at esp + 28 = 0
```

## Reading a full function: example

```asm
push   %ebp                  ; save caller's frame
mov    %esp,%ebp             ; set up our frame
and    $0xfffffff0,%esp      ; align stack to 16 bytes
sub    $0x50,%esp            ; reserve 80 bytes for locals
lea    0x10(%esp),%eax       ; eax = address of buffer at esp+16
mov    %eax,(%esp)           ; 1st argument = buffer address
call   <gets@plt>            ; gets(buffer)
leave                        ; restore caller's frame
ret                          ; return
```

Translated to C:
```c
void main(void) {
    char buffer[64];          // 0x50 - 0x10 = 64 bytes
    gets(buffer);
    return;
}
```

## Examining memory

### x command: examine memory

Format: `x/NFU address`
- **N** = number of units to display
- **F** = format (x=hex, s=string, i=instruction, d=decimal, c=char)
- **U** = unit size (b=byte, h=halfword/2 bytes, w=word/4 bytes)

```bash
(gdb) x/s 0x8048570          # string at address
"Good... Wait what?\n"

(gdb) x/10x $esp             # 10 hex words from stack top
0xbffff650: 0xbffff660 0x00000001 0x00000013 0xb7fd1ac0

(gdb) x/i 0x8048490          # instruction at address
0x8048490: call 0x8048340 <gets@plt>

(gdb) x/20x $esp             # inspect 20 words of stack (useful for overflow)
```

### Print command

```bash
(gdb) p system                # address of system()
(gdb) p run                   # address of run()
(gdb) p/x 423                # decimal to hex → 0x1a7
(gdb) p/d 0x1a7              # hex to decimal → 423
(gdb) p/x $eax               # value of eax in hex
```

## Finding the overflow offset

### Method 1: Calculate from disassembly

```asm
sub    $0x50,%esp             ; total stack space = 0x50 = 80 bytes
lea    0x10(%esp),%eax        ; buffer starts at esp + 0x10 = esp + 16
```

Buffer size = 80 - 16 = 64 bytes. Add saved EBP (4 bytes) and any alignment padding. Test with increasing values until EIP = 0x42424242.

### Method 2: Binary search

```bash
(gdb) run < <(python -c "print('A' * 70 + 'BBBB')")
# check EIP: if not 0x42424242, increase
(gdb) run < <(python -c "print('A' * 76 + 'BBBB')")
# EIP = 0x42424242 → offset is 76
```

### Method 3: Unique pattern

Generate a pattern where every 4 bytes are unique:

```bash
(gdb) run < <(python -c "print('Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9')")
# EIP = 0x63413163 → look up this value in the pattern to find the offset
```

## Breakpoints and stepping

```bash
(gdb) b main                  # break at function
(gdb) b *0x08048490           # break at exact address
(gdb) r                       # run until breakpoint
(gdb) ni                      # next instruction (step over calls)
(gdb) si                      # step instruction (step into calls)
(gdb) c                       # continue to next breakpoint
(gdb) info breakpoints        # list breakpoints
(gdb) delete 1                # delete breakpoint number 1
```

## Inspecting state at a breakpoint

```bash
(gdb) info registers          # all registers
(gdb) info register eip       # just EIP
(gdb) x/20x $esp             # stack contents
(gdb) x/s $eax               # string that eax points to
(gdb) bt                      # backtrace: show call stack
```

## Workflow for each level

1. **List functions**: `info functions`
2. **Disassemble main**: `disas main`
3. **Disassemble interesting functions**: `disas <name>`
4. **Check strings**: `x/s <address>` for values loaded before calls
5. **Identify vulnerability**: gets? printf(user_input)? strcpy?
6. **Calculate offset**: from disassembly or by testing
7. **Find target address**: `p run`, `p system`, etc.
8. **Test exploit**: `run < <(python -c "print(payload)")`
9. **Run outside GDB**: `(python -c "print(payload)"; cat) | ./binary`

## AT&T vs Intel syntax

GDB uses AT&T syntax by default. The main differences:

| | AT&T (GDB default) | Intel |
|---|---|---|
| Order | `mov source, dest` | `mov dest, source` |
| Registers | `%eax` | `eax` |
| Immediates | `$0x1a7` | `0x1a7` |
| Memory | `0x10(%esp)` | `[esp + 0x10]` |

To switch to Intel syntax in GDB:
```bash
(gdb) set disassembly-flavor intel
```

Both syntaxes mean the same thing with different notation.
