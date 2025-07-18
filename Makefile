BUILDDIR	:= build

GWPROXYSRC	:= gwproxy.c gwdnslib.c gwsocks5lib.c linux.c general.c
CONVERTERSRC	:= ip_converter.c general.c
INOTIFYSRC	:= test_inotify.c linux.c
DNSRESOLVSRC	:= dns_resolver.c general.c linux.c
DNSCLIENTSRC	:= dns_client.c general.c linux.c
GWSOCKS5LIBSRC	:= gwsocks5lib.c linux.c general.c
GWDNSLIBSRC	:= gwdnslib.c linux.c

OBJS1		:= $(patsubst %.c,$(BUILDDIR)/%.o,$(GWPROXYSRC))
OBJS2		:= $(patsubst %.c,$(BUILDDIR)/%.o,$(CONVERTERSRC))
OBJS3		:= $(patsubst %.c,$(BUILDDIR)/%.o,$(INOTIFYSRC))
OBJS4		:= $(patsubst %.c,$(BUILDDIR)/%.o,$(DNSRESOLVSRC))
OBJS5		:= $(patsubst %.c,$(BUILDDIR)/%.o,$(DNSCLIENTSRC))
OBJS6		:= $(patsubst %.c,$(BUILDDIR)/%.o,$(GWSOCKS5LIBSRC))
OBJS7		:= $(patsubst %.c,$(BUILDDIR)/%.o,$(GWDNSLIBSRC))

TARGET1		:= $(BUILDDIR)/gwproxy
TARGET2		:= $(BUILDDIR)/ip_converter
TARGET3		:= $(BUILDDIR)/test_inotify
TARGET4		:= $(BUILDDIR)/dns_resolver
TARGET5		:= $(BUILDDIR)/dns_client
TARGET6		:= $(BUILDDIR)/gwsocks5lib
TARGET7		:= $(BUILDDIR)/gwdnslib

CC		:= gcc
CFLAGS		:= -Wmaybe-uninitialized -Wall -Wextra -Os
# LDFLAGS		:= -fsanitize=address -lasan -fsanitize=undefined

BUFF_SIZE = $$((1024 * 1024 * 10))

all: $(TARGET1) $(TARGET2) $(TARGET3) $(TARGET4) $(TARGET5) $(TARGET6)

$(BUILDDIR):
	mkdir -p $@

$(BUILDDIR)/%.o: %.c | $(BUILDDIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -c $< -o $@

$(TARGET1): $(OBJS1)
$(TARGET2): $(OBJS2)
$(TARGET3): $(OBJS3)
$(TARGET4): $(OBJS4)
$(TARGET5): $(OBJS5)
$(TARGET6): CFLAGS += -DRUNTEST  -DENABLE_DUMP
$(TARGET6): $(OBJS6)
$(TARGET7): CFLAGS += -DRUNTEST
$(TARGET7): $(OBJS7)

# test without log: make CFLAGS="-DENABLE_LOG=false" -B test_conventional
test_conventional: $(TARGET1)
	$< -t [::1]:8081 -b [::1]:8080 -T 1
test_socks5_silent: CFLAGS += -DENABLE_DUMP=false -DENABLE_LOG=false
test_socks5_silent: $(TARGET1)
	$< -g $(BUFF_SIZE) -s -b [::]:1080 -T 500 -w 60 -y 500
test_socks5_nodump: CFLAGS += -DENABLE_DUMP=false
test_socks5_nodump: $(TARGET1)
	$< -g $(BUFF_SIZE) -s -b [::]:1080 -T 1 -w 60 2>&1 | grep -v verbose | grep -v debug
test_socks5: CFLAGS += -DENABLE_LOG=false -DENABLE_DUMP=true
test_socks5: $(TARGET1)
	$< -g $(BUFF_SIZE) -s -b [::]:1080 -T 1 -w 60
test_socks5_valgrind: $(TARGET1)
	valgrind --leak-check=full --leak-resolution=high --log-file=leaks.log $< -s -b [::]:1080 -T 50 -y 50 -w 60
test_socks5_strace: CFLAGS += -DENABLE_LOG=false
test_socks5_strace: $(TARGET1)
	strace -x -f $< -f ./auth.db -s -b [::]:1080 -T 1 -w 60
test_dns_serv: $(TARGET4)
	$< -b [::]:6969 -t 1
stress_test: $(TARGET5)
	$< -n google.com -s [::1]:6969
test_gwsocks5lib: $(TARGET6)
	$<

.PHONY: clean
clean:
	rm -rf $(BUILDDIR)/*.o $(TARGET1) $(TARGET2) $(TARGET3) $(TARGET4) $(TARGET5) $(TARGET6)
