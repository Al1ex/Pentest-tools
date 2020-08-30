# for portability.
SHELL   = /bin/sh
CC      = gcc

# compile flags.
CFLAGS  = -g -std=c99 -pedantic -Wall -Wextra -Werror -march=native -O2 -fwhole-program -flto

TARGET  = icmptunnel
MANPAGE = icmptunnel.8
SOURCES = $(shell echo src/*.c)
HEADERS = $(shell echo src/*.h)
OBJECTS = $(SOURCES:.c=.o)
VERSION = 0.1-beta

# installation paths.
PREFIX  = $(DESTDIR)/usr/local
BINDIR  = $(PREFIX)/sbin
MANDIR  = $(PREFIX)/share/man/man8

# standard targets.
all: $(TARGET)

$(TARGET): $(OBJECTS)
	@echo "[LD] $@"
	@$(CC) $(CFLAGS) -o $(TARGET) $(OBJECTS)

man:
	@(cd man; gzip < $(MANPAGE) > $(MANPAGE).gz)

install: $(TARGET) man
	@install -D -m 755 $(TARGET) $(BINDIR)/$(TARGET)
	@install -D -m 744 man/$(MANPAGE).gz $(MANDIR)/$(MANPAGE).gz

install-strip: $(TARGET) man
	@install -D -m 755 -s $(TARGET) $(BINDIR)/$(TARGET)
	@install -D -m 744 man/$(MANPAGE).gz $(MANDIR)/$(MANPAGE).gz

uninstall:
	@$(RM) $(BINDIR)/$(TARGET)
	@$(RM) $(MANDIR)/$(MANPAGE).gz

clean:
	@$(RM) $(OBJECTS)

distclean: clean
	@$(RM) $(TARGET)
	@(cd man; $(RM) $(MANPAGE).gz)

%.o: %.c $(HEADERS)
	@echo "[CC] $<"
	@$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: all man install install-strip uninstall clean distclean
