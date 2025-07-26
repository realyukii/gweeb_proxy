BUILDDIR	:= build

GWPROXYSRC	:= gwproxy.c gwdnslib.c gwsocks5lib.c linux.c general.c
CONVERTERSRC	:= ip_converter.c general.c
INOTIFYSRC	:= test_inotify.c linux.c
DNSCLIENTSRC	:= dnsclient.c general.c gwdnsparserlib.c
GWSOCKS5LIBSRC	:= gwsocks5lib.c linux.c general.c
GWDNSLIBSRC	:= gwdnslib.c linux.c

OBJS1		:= $(patsubst %.c,$(BUILDDIR)/%.o,$(GWPROXYSRC))
OBJS2		:= $(patsubst %.c,$(BUILDDIR)/%.o,$(CONVERTERSRC))
OBJS3		:= $(patsubst %.c,$(BUILDDIR)/%.o,$(INOTIFYSRC))
OBJS5		:= $(patsubst %.c,$(BUILDDIR)/%.o,$(DNSCLIENTSRC))
OBJS6		:= $(patsubst %.c,$(BUILDDIR)/%.o,$(GWSOCKS5LIBSRC))
OBJS7		:= $(patsubst %.c,$(BUILDDIR)/%.o,$(GWDNSLIBSRC))

TARGET1		:= $(BUILDDIR)/gwproxy
TARGET2		:= $(BUILDDIR)/ip_converter
TARGET3		:= $(BUILDDIR)/test_inotify
TARGET5		:= $(BUILDDIR)/dnsclient
TARGET6		:= $(BUILDDIR)/gwsocks5lib
TARGET7		:= $(BUILDDIR)/gwdnslib

CC		:= gcc
CFLAGS		:= -Wmaybe-uninitialized -Wall -Wextra -Os -g3
# LDFLAGS		:= -fsanitize=address -lasan -fsanitize=undefined

BUFF_SIZE = $$((1024 * 5))

all: $(TARGET1) $(TARGET2) $(TARGET3) $(TARGET5) $(TARGET6)

$(BUILDDIR):
	mkdir -p $@

$(BUILDDIR)/%.o: %.c | $(BUILDDIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -c $< -o $@

$(TARGET1): $(OBJS1)
$(TARGET2): $(OBJS2)
$(TARGET3): $(OBJS3)
$(TARGET5): LDFLAGS += -luring
$(TARGET5): $(OBJS5)
$(TARGET6): CFLAGS += -DRUNTEST  -DENABLE_DUMP
$(TARGET6): $(OBJS6)
$(TARGET7): CFLAGS += -DRUNTEST
$(TARGET7): $(OBJS7)

# test without log: make CFLAGS="-DENABLE_LOG=false" -B test_conventional
test_conventional: $(TARGET1)
	$< -t [::1]:8081 -b [::1]:8080 -T 1
test_socks5: CFLAGS += -DENABLE_LOG=false -DENABLE_DUMP=true
test_socks5: $(TARGET1)
	$< -g $(BUFF_SIZE) -s -b [::]:1080 -T 1 -w 60
test_dnsclient: $(TARGET5)
	$< 1.1.1.1 53 google.com github.com facebook.com
test_gwsocks5lib: $(TARGET6)
	$<

.PHONY: clean
clean:
	rm -rf $(BUILDDIR)/*.o $(TARGET1) $(TARGET2) $(TARGET3) $(TARGET5) $(TARGET6)
