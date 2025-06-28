me:
I got this warning:
```
general.c:60:12: warning: ‘init_addr’ defined but not used [-Wunused-function]
   60 | static int init_addr(const char *addr, struct sockaddr_storage *addr_st)
      |            ^~~~~~~~~
linux.c:44:12: warning: ‘parse_auth_file’ defined but not used [-Wunused-function]
   44 | static int parse_auth_file(int filefd, struct userpwd_list *l, char **buf)
```

how to tell compiler that static function is used elsewhere in the code base?

ChatGPT:
In C, marking a function `static` gives it *internal linkage*—the compiler assumes it can only ever be called from within that one “.c” file.  If you really are calling it from *another* translation unit, the fix is to **remove** `static` and put an `extern` declaration in a header.  But if you want to keep it `static` and simply suppress the “defined but not used” warning (for example, because it’s invoked indirectly via a function‑pointer table or via `dlsym()`), you have two common options:

---

### 1. Change linkage to external

If you intend to call it from elsewhere, drop `static`:

```c
// in addr.h
#ifndef ADDR_H
#define ADDR_H
int init_addr(const char *addr, struct sockaddr_storage *addr_st);
#endif

// in linux.c
#include "addr.h"
int init_addr(const char *addr, struct sockaddr_storage *addr_st) {
    /* … */
}
```

This way the compiler knows it has external linkage, you can call it from any other “.c” file, and the warning goes away.

---

### 2. Keep it `static`, but tell GCC/Clang it really is “used”

If you don’t want to change its linkage but do want to prevent the warning, attach one of these attributes to the definition:

```c
// tells the compiler “don’t warn me if it looks unused”
static __attribute__((unused))
int parse_auth_file(int filefd, struct userpwd_list *l, char **buf)
{
    /* … */
}

// or, if you also want to force it to be emitted (not optimized away)
static __attribute__((used))
int init_addr(const char *addr, struct sockaddr_storage *addr_st)
{
    /* … */
}
```

- `__attribute__((unused))` silences the `-Wunused-function` warning.
- `__attribute__((used))` also prevents the optimizer from stripping out a seemingly “unused” static function.

---

### 3. Suppress the warning with pragmas (per‐function)

You can also locally disable the warning around those definitions:

```c
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

static int init_addr(…)
{
    /* … */
}

#pragma GCC diagnostic pop
```

---

**In summary:**

* If you truly need other files to call it, **remove** `static` and declare it in a header.
* If you just want to keep it `static` but tell the compiler “trust me, it’s used,” annotate it with `__attribute__((used))` or `__attribute__((unused))`, or use a diagnostic `#pragma` to mute the warning.

me:
but when I remove the static keyword or add extern keyword, linker complaint and yelling to me:
```
$  make test_socks5 
gcc -Wmaybe-uninitialized -DDEBUG_LVL=0 -Wall -Wextra gwproxy.c general.c linux.c -o build/gwproxy
/usr/bin/ld: /tmp/ccCRNNGG.o: in function `init_addr':
general.c:(.text+0x0): multiple definition of `init_addr'; /tmp/ccTYQqTw.o:gwproxy.c:(.text+0x0): first defined here
/usr/bin/ld: /tmp/ccL5LFds.o: in function `parse_auth_file':
linux.c:(.text+0x0): multiple definition of `parse_auth_file'; /tmp/ccTYQqTw.o:gwproxy.c:(.text+0x1fd): first defined here
collect2: error: ld returned 1 exit status
make: *** [Makefile:10: build/gwproxy] Error 1
```

I still don't understand why `ld` angry and yelling to me even though gwproxy.c have no definition of `parse_auth_file` and `init_addr` function, the gwproxy.c only call it, not define nor declare.

ChatGPT:
Ah, I see what's happening now. The issue is that by removing "static" or adding "extern," you're potentially allowing the linker to find multiple definitions of the same function — in general.c, linux.c, and possibly gwproxy.c. Even if gwproxy.c only calls the functions, the linker is still seeing them as defined in more than one place. The static keyword restricts the scope to one file, preventing this conflict. It seems the solution is to keep static or carefully use extern if you want one function definition across the codebase.

When you removed `static`, you made those functions have *external* linkage, so every object file that “sees” a definition of `init_addr` or `parse_auth_file` will emit the same symbol into its `.o`.  At link time, the linker spots two (or three) copies of the same symbol and pukes with “multiple definition.”

From your error it even looks like you’re compiling all three sources in one go:

```bash
gcc … gwproxy.c general.c linux.c -o gwproxy
```

If you happen to `#include "general.c"` or `#include "linux.c"` inside `gwproxy.c`, that means:

1. The body of `init_addr` and `parse_auth_file` gets compiled into **gwproxy.o** (because of the `#include`).
2. You’re also separately compiling **general.c** and **linux.c** into their own `.o` files.
3. Now you have two definitions of each symbol (one in gwproxy.o, one in general.o or linux.o), and the linker refuses to pick one.

---

## How to fix it

1. **Don’t `#include` `.c` files.**
   Only ever `#include` headers.  Move your prototypes into, say, `general.h` and `linux.h`, and in `gwproxy.c` do:

   ```c
   #include "general.h"
   #include "linux.h"
   ```

   Then in your Makefile or build command compile each `.c` separately:

   ```bash
   gcc -c general.c   # produces general.o
   gcc -c linux.c     # produces linux.o
   gcc -c gwproxy.c   # produces gwproxy.o
   gcc general.o linux.o gwproxy.o -o build/gwproxy
   ```

2. **Give each function exactly one definition.**
   If you really want `init_addr` and `parse_auth_file` to be callable from multiple `.c` files, remove `static` **only** in their one .c file (where you actually wrote the code), and leave them out of every other .c.  All other .c’s just `#include` the header with:

   ```c
   // general.h
   int init_addr(const char *addr, struct sockaddr_storage *addr_st);
   ```

3. **If you don’t intend them to be shared, keep them `static`.**
   The “unused” warning means they’re not used *in that file*.  If they’re really only ever called via a function‑pointer table or `dlsym()`, but *not* directly, then silence the warning with one of:

   ```c
   static __attribute__((used))
   int init_addr(…)
   { … }

   // or

   #pragma GCC diagnostic push
   #pragma GCC diagnostic ignored "-Wunused-function"
   static int parse_auth_file(…)
   { … }
   #pragma GCC diagnostic pop
   ```

---

### TL;DR

* **Static** functions live *only* in the .o where they’re defined—other files can’t call them.
* **Removing `static`** makes them external, but then you must ensure **only one** object file ever defines each one.
* The linker error you saw means you ended up with two copies of the same symbol (most likely because you `#include`d a .c into another .c while also compiling that .c separately).  The cure is to split out prototypes into headers, compile each .c only once, and link them.

me:
> From your error it even looks like you’re compiling all three sources in one go:

alright, it seems I need to refactor my Makefile script to fix this, thank you very much for this fruitful conversation!

here's my refactored Makefile script:
```
<Makefile content>
```

it works pretty well, now I learned why I need header file and compile each C source into separate object file and linking it together.

ChatGPT:
That Makefile is looking solid! A few more tweaks you might consider to make it even more robust:

1. **Add a `clean` target** so you can easily wipe out all build artifacts:

   ```make
   .PHONY: clean
   clean:
    rm -rf $(BUILDDIR)/*.o $(TARGET1) $(TARGET2) $(TARGET3)
   ```
2. **Declare your phony targets** (`all`, `clean`, `test_conventional`, `test_socks5`) to avoid name clashes if you ever have files by those names:

   ```make
   .PHONY: all test_conventional test_socks5
   ```
3. **Enable parallel builds** by making your object rules fully independent—GCC’s `-MMD -MP` flags will auto‑generate dep‑files so that whenever you change a header, only the affected `.o` rebuilds. For example:

   ```make
   CFLAGS += -MMD -MP
   -include $(OBJS1:.o=.d) $(OBJS2:.o=.d) $(OBJS3:.o=.d)
   ```
4. **Allow override of `CC` or `CFLAGS`** by users on the command line (you already do this implicitly, but you can document it):

   ```make
   # override like: make CFLAGS="-O2 -g"
   ```
5. **Use built‑in variables** for compactness:

   ```make
   $(BUILDDIR)/%.o: %.c | $(BUILDDIR)
    $(CC) $(CFLAGS) -c $< -o $@
   ```

   (You’ve already done this nicely.)

With those additions, you’ll have a “one‑stop” build system that’s clean, efficient, and flexible. Great work getting the linkage sorted out!
