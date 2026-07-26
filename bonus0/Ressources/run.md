# bonus0: run it

```bash
cd ~
python /tmp/exploit.py
```

(copy `exploit.py` to `/tmp` first, the account's home directory is read-only; must be run with `~` as the current directory since it calls `./bonus0`)

If it prints no shell/flag, just run it again, that means the address it measured didn't survive to the actual run.
