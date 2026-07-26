# Bonus 3

SUID **end**. Final level. `buffer[atoi(argv[1])] = 0` drops a null byte at an attacker-chosen index, then compares the (truncated) real password to `argv[1]` itself.

1. `argv[1] = ""` sidesteps the whole thing: `atoi("") == 0` truncates `buffer` to `""`, and `strcmp("", "")` is always true, no matter what the real password is.
   ```
   ./bonus3 ""
   id
   uid=2013(bonus3) [...] euid=2014(end) [...]
   cat /home/user/end/.pass
   ```
   (Any other value fails: e.g. `"abc"` also gives `atoi()==0`, but then `strcmp("", "abc")` isn't equal.)

`Ressources/exploit.py` runs this over SSH against the real target.

Flag: `3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c`
