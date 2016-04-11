CC?=cc
CXXFLAGS?=-O2 -Wall
LRUN_GROUP?=lrun
INSTALL?=install

ifeq ($(DESTDIR),)
PREFIX?=/usr/local
SUDO?=sudo
else
PREFIX?=/usr
SUDO?=env
endif

.PHONY: all clean

all: netns-empty

install: netns-empty
	$(SUDO) $(INSTALL) -D -m4550 -oroot -g$(LRUN_GROUP) -s $< $(DESTDIR)$(PREFIX)/bin/lrun-netns-empty

clean:
	-rm -f *.o netns-empty

%.o: %.cc
	$(CC) -std=c99 $(CXXFLAGS) $^ -c -o $@

netns-empty: netns-empty.o
	$(CC) $(LDFLAGS) $^ -o $@
