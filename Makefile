BUILDDIR	:= build

GWPROXYSRC	:= gwproxy.c linux.c general.c
CONVERTERSRC	:= ip_converter.c general.c
INOTIFYSRC	:= test_inotify.c linux.c

OBJS1		:= $(patsubst %.c,$(BUILDDIR)/%.o,$(GWPROXYSRC))
OBJS2		:= $(patsubst %.c,$(BUILDDIR)/%.o,$(CONVERTERSRC))
OBJS3		:= $(patsubst %.c,$(BUILDDIR)/%.o,$(INOTIFYSRC))

TARGET1		:= $(BUILDDIR)/gwproxy
TARGET2		:= $(BUILDDIR)/ip_converter
TARGET3		:= $(BUILDDIR)/test_inotify

CC		:= gcc
CFLAGS		:= -Wmaybe-uninitialized -DDEBUG_LVL=0 -Wall -Wextra -g3

all: $(TARGET1) $(TARGET2) $(TARGET3)

$(BUILDDIR):
	mkdir -p $@

$(BUILDDIR)/%.o: %.c | $(BUILDDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET1): $(OBJS1)
	$(CC) $^ -o $@
$(TARGET2): $(OBJS2)
	$(CC) $^ -o $@
$(TARGET3): $(OBJS3)
	$(CC) $^ -o $@

test_conventional: $(TARGET1)
	$< -t [::1]:8081 -b [::1]:8080 -T 1
test_socks5: $(TARGET1)
	$< -f ./auth.db -s -b [::]:1080 -T 1 -w 60

.PHONY: clean
clean:
	rm -rf $(BUILDDIR)/*.o $(TARGET1) $(TARGET2) $(TARGET3)
