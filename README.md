# Rainfall

Binary exploitation project on an i386 system. Each level contains a SUID binary to exploit in order to escalate to the next user and read their `.pass` file.

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
scp -P 4242 level0@<VM_IP>:/home/user/level0/level0 level0/Ressources/
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

| Level | Technique |
|-------|-----------|
| 0 | Hardcoded magic number (atoi comparison) |
| 1 | Buffer overflow → ret2function |
| 2 | Buffer overflow → shellcode on heap via strdup |
| 3 | Format string → %n to write global |
| 4 | Format string → %hn split write to large target |
| 5 | - |
| 6 | - |
| 7 | - |
| 8 | - |
| 9 | - |
| bonus0 | - |
| bonus1 | - |
| bonus2 | - |
| bonus3 | - |

Techniques will be filled in as each level is solved.
