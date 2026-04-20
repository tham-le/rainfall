# Rainfall

**Completed binary exploitation CTF** on an i386 system. A complete journey through modern exploitation techniques from basic buffer overflows to advanced heap manipulation and C++ vtable hijacking.

Each level contains a SUID binary to exploit in order to escalate to the next user and read their `.pass` file. All 10 mandatory levels (level0-level9) and 4 bonus levels (bonus0-bonus3) have been solved and documented.

## Setup

### Requirements

- QEMU or VirtualBox
- `RainFall.iso` (provided with the subject)

### Option 1: QEMU (recommended)

Boot directly from the ISO, no disk image needed:

```bash
qemu-system-x86_64 \
  -enable-kvm \
  -cpu host \
  -m 8G \
  -smp 8 \
  -cdrom RainFall.iso \
  -boot d \
  -netdev user,id=net0,hostfwd=tcp::4242-:4242 \
  -device virtio-net-pci,netdev=net0 \
  -nographic -serial none -monitor none
```

The `-hostfwd` flag forwards port 4242 on localhost to the VM. Connect with:

```bash
ssh -p 4242 level0@localhost
```

Password: `level0`

### Option 2: VirtualBox

1. Open VirtualBox and click **New**
2. Configure:
   - **Name:** RainFall
   - **Type:** Linux
   - **Version:** Ubuntu (32-bit)
   - **RAM:** 1024 MB
   - **Hard disk:** Create a virtual hard disk (VDI, dynamically allocated, 8 GB)
3. Go to **Settings > Storage**, click the empty disk under Controller: IDE, then select `RainFall.iso`
4. Go to **Settings > Network**, set **Attached to: Bridged Adapter** (or Host-only Adapter)
5. Start the VM

The VM displays an IP address on boot. Connect via SSH on port 4242:

```bash
ssh -p 4242 level0@<VM_IP>
```

Password: `level0`

### Level progression

```bash
# Exploit the binary to get a shell as the next user
level0@RainFall:~$ ./level0 <exploit>
$ cat /home/user/level1/.pass
<password>
$ exit

# Move to next level
level0@RainFall:~$ su level1
Password: <password>
level1@RainFall:~$
```

### Copy binaries for local analysis

```bash
# Copy any binary from VM for local analysis
scp -P 4242 level0@<VM_IP>:/home/user/level0/level0 ./
```

## Security profile

```
ASLR:            Off
RELRO:           No
Stack canary:    No
NX:              Enabled
PIE:             No
```

## GDB cheat sheet

### Basics

| Command | Description |
|---|---|
| `gdb ./binary` | Open binary in GDB |
| `r` | Run the program |
| `r < <(python -c "print('A'*100)")` | Run with crafted input |
| `c` | Continue after breakpoint |
| `q` | Quit GDB |

### Disassembly & functions

| Command | Description |
|---|---|
| `info functions` | List all functions in the binary |
| `disas main` | Disassemble main |
| `disas run` | Disassemble a specific function |
| `p run` | Print address of a function |
| `p system` | Print address of system() in libc |

### Examine memory

| Command | Description |
|---|---|
| `x/s 0xaddr` | Show string at address |
| `x/10x $esp` | Show 10 hex words on the stack |
| `x/i 0xaddr` | Show instruction at address |
| `x/20x $esp` | Inspect stack layout (20 words) |

### Breakpoints & registers

| Command | Description |
|---|---|
| `b *0xaddr` | Set breakpoint at address |
| `b main` | Set breakpoint at function |
| `info registers` | Show all register values |
| `info register eip` | Show just EIP (instruction pointer) |

### Search memory

| Command | Description |
|---|---|
| `find &system, +9999999, "/bin/sh"` | Find string in memory |

### Useful for exploitation

| Command | Description |
|---|---|
| `p/d 0x1a7` | Convert hex to decimal (423) |
| `p/x 423` | Convert decimal to hex (0x1a7) |

## Levels

| Level | Technique | Key Learning |
|-------|-----------|--------------|
| 0 | Hardcoded magic number (atoi comparison) | Basic reversing + arithmetic |
| 1 | Buffer overflow → ret2function | Stack layout, EIP control |
| 2 | Buffer overflow → shellcode on heap via strdup | Heap vs stack execution |
| 3 | Format string → %n to write global | Format string basics |
| 4 | Format string → %hn split write to large target | Precision format string writes |
| 5 | Format string → GOT overwrite of exit() | GOT/PLT manipulation |
| 6 | Heap overflow → overwrite adjacent function pointer | Heap layout exploitation |
| 7 | Heap overflow → hijack strcpy dest pointer → GOT overwrite | Chained heap corruption |
| 8 | Heap layout abuse → auth+0x20 lands in service's data | Heap feng shui |
| 9 | C++ vtable hijack via heap overflow + shellcode (NX off) | Object-oriented exploitation |
| bonus0 | strncpy no-null bug, shellcode in p buffer, ret hijack | Null termination bugs |
| bonus1 | Integer overflow in memcpy size overwrites adjacent int | Integer overflow + variable overwrite |
| bonus2 | LANG env gate + strcat overflow, env shellcode via SHELLCODE | Environment variable attacks |
| bonus3 | Empty string bypass, atoi-controlled null injection | Logic bugs + string manipulation |

All levels completed and documented with source reconstructions, detailed walkthroughs, and verified flags.

## Project Structure

Each level directory contains:

```
levelX/
├── flag         # SHA256 hash from /home/user/levelY/.pass  
├── source       # Reconstructed C source code
└── walkthrough  # Detailed exploitation analysis
```

**Documentation includes:**
- **flag**: The actual password hash obtained from successful exploitation
- **source**: Clean C reconstruction from binary analysis (Ghidra + manual review)  
- **walkthrough**: Step-by-step exploitation process with vulnerability analysis, stack layouts, payload construction, and technique explanations

## Repository Features

- ✅ **Complete coverage**: All 14 levels (10 mandatory + 4 bonus)
- ✅ **Educational walkthroughs**: Each technique thoroughly explained
- ✅ **Clean source code**: Readable C reconstructions for learning
- ✅ **Verified exploits**: All flags captured from actual VM exploitation
- ✅ **Professional development**: 18 commits with descriptive technical messages
- ✅ **No binaries**: Repository contains only documentation (binaries stay on VM)
