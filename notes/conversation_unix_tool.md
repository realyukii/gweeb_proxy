context: the conversation emerge/started when I'm testing the effectiveness of optimization for adjusting epoll events (see 828b462ad3263211f405c02b994e019c9c93d45b)

just info: you can list open file fd on the bash process by:
```bash
ls -l /proc/$$/fd
```

me:
print raw binary with `printf(1)`

ChatGPT:
To emit arbitrary byte values (including NULs) with the standard shell `printf` (man section 1), you embed C-style escape sequences in the format string. Here are the key techniques:

---

### 1. Hex (`\xHH`) and octal (`\0NNN`) escapes

Most `printf(1)` implementations recognize:

* `\xHH` – two-digit hex value
* `\0NNN` – up to three-digit octal value

```sh
# Print a single NUL byte, then 0xFF, then a newline:
printf '\x00\xFF\n'

# Same thing using octal escapes:
printf '\000\377\n'
```

---

### 2. Using `%b` to interpret backslashes in arguments

Some shells’ built-in `printf` only interpret escapes in the format string, not in the arguments.  To force escape-processing on an argument, use the `%b` conversion:

```sh
# Argument is '\x41\x42' → prints 'AB'
printf '%b\n' '\x41\x42'
```

---

### 3. Writing a full 0x00–0xFF dump

If you need all 256 byte values in a file:

```sh
# (a) build a sequence of \x00 \x01 … \xFF
seq -f '\\x%02x' 0 255 | tr -d '\n' \
  | xargs printf '%b' \
  > all_bytes.bin
```

Explanation:

1. `seq -f '\\x%02x' 0 255` generates `\x00\n\x01\n…\xFF\n`
2. `tr -d '\n'` joins them into one long `\x00\x01…\xFF` string
3. `xargs printf '%b'` feeds that to `printf` with `%b` so the escapes become raw bytes

---

### 4. Redirecting to a file

Simply redirect stdout:

```sh
# Print bytes 0x00, 0x01, 0x02 into file.bin
printf '\x00\x01\x02' > file.bin
```

---

#### Tips & portability

* If your `/bin/printf` doesn’t support `\xHH`, stick to octal `\0NNN`.

* On systems where `printf` is a shell builtin (bash, zsh), you can also use the special `$'…'` quoting:

  ```sh
  # same as printf '\x00\xFF\n'
  printf $'\x00\xFF\n'
  ```

* To print a literal backslash or percent sign:

  ```sh
  printf '\\'   # prints \
  printf '%%'   # prints %
  ```

With those techniques you can generate **any** raw binary sequence purely from the `printf(1)` command.

me:
```
 printf "\x05\x01\x00" | nc ::1 1080 | xxd
```

let say I want to send another byte after certain interval of time, how to do that in this case?

ChatGPT:
You can’t ask `printf` itself to pause mid‐stream, but you can insert a `sleep` between two `printf` calls in a shell‐group (or use a persistent connection).  Here are two simple approaches:

---

## 1. Pipe a grouped sequence with `sleep`

Bash (and most shells) will run everything in `{ …; }` as one “producer” of stdin to `nc`, so the connection stays open until your last `printf` (and the subshell exits):

```bash
{
  # first 3 bytes
  printf '\x05\x01\x00'
  # wait 2 seconds
  sleep 2
  # then one more byte
  printf '\x06'
} | nc ::1 1080 | xxd
```

You can chain as many `sleep`+`printf` steps as you like:

```bash
{
  printf '\x05\x01\x00';  sleep 1
  printf '\x06';          sleep 0.5
  printf '\x07\x08'
} | nc ::1 1080 | xxd
```

Note: if your `nc` closes as soon as its stdin is closed, you’re fine; if it has a `-q` or `-N` option, you can use that to delay shutdown until your subshell fully exits.

---

## 2. Use a persistent TCP “file” via `/dev/tcp`

Bash (and ksh-86) let you open a TCP socket as a file descriptor.  Then you can write, sleep, write, etc., as separate statements:

```bash
# open FD 3 for read/write on ::1 port 1080
exec 3<>/dev/tcp/::1/1080

# send first bytes
printf '\x05\x01\x00' >&3

# pause
sleep 1

# send another byte
printf '\x06' >&3

# (optional) read the response and hexdump it
cat <&3 | xxd

# close FD 3
exec 3>&- 3<&-
```

This gives you full programmatic control over timing without having to keep everything in one pipe.

---

## 3. (Advanced) Bash coprocess

You can also use Bash’s `coproc` to manage `nc` as a background job:

```bash
coproc NC { nc ::1 1080 | xxd; }
# NC is an array: NC[0]=read-fd, NC[1]=write-fd

# send
printf '\x05\x01\x00' >&"${NC[1]}"
sleep 1
printf '\x06'             >&"${NC[1]}"

# when you’re done
kill $COPROC_PID
```

---

### Notes

* `sleep` accepts fractional seconds (e.g. `sleep 0.1`) if your `sleep` supports it.
* Use `-q` or `-N` on GNU netcat if it’s closing too soon.
* In all cases, the trick is: **don’t close the connection** until after your final `printf`, so group your commands (or keep the FD open) around the sleeps.

me:
hmm why no output from xxd, even though the socket have received some data?

ChatGPT:

you never see anything because:

1. **`cat <&3` waits for EOF.**
   You’ve left the TCP socket open (you only do `exec 3>&-` *after*), so `cat` will sit there waiting for the connection to close before it flushes out whatever it has buffered.


---

### How to actually see the bytes

#### 1) Read a fixed number of bytes

If you know the server should send you 2 bytes (e.g. version+method), use `head` or `dd` so your reader exits immediately:

```bash
exec 3<>/dev/tcp/127.0.0.1/1080
# send greeting
printf '\x05\x01\x00' >&3
# read exactly 2 bytes and dump them
head -c2 <&3 | xxd
# → you’ll see something like “0000000: 0500”
```

You can then

```bash
sleep 1
# send a proper SOCKS5 CONNECT (not just \x06)
printf '\x05\x01\x00\x03' >&3
head -c10 <&3 | xxd   # read the connect‐reply
```

#### 2) Force an EOF so `cat` quits

If you really want to use `cat | xxd`, you must close FD 3 *before* `cat` runs so that it sees EOF:

```bash
{
  exec 3<>/dev/tcp/127.0.0.1/1080
  printf '\x05\x01\x00' >&3
  sleep 1
  printf '\x06' >&3
  exec 3>&-   # CLOSE the socket here
} | xxd
```

Here the entire `{…}` is piped to `xxd`, and when you `exec 3>&-` inside that block you drop the last open copy of the socket—`xxd` then gets an EOF and will immediately dump whatever bytes it has.

#### TL;DR

* **`cat <&3 | xxd` won’t show you anything** until the socket is closed (EOF) or until you read a *fixed* number of bytes.
* **Use** `head -cN <&3 | xxd` **or** `dd bs=1 count=N <&3 | xxd` **to grab exactly N bytes**, or explicitly close FD 3 in a grouped pipeline so that `xxd` sees EOF and flushes.
