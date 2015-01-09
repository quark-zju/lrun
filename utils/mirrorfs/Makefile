CXX?=g++
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

all: mirrorfs

install: mirrorfs
	$(SUDO) $(INSTALL) -D -m4550 -oroot -g$(LRUN_GROUP) -s $< $(DESTDIR)$(PREFIX)/bin/lrun-mirrorfs

clean:
	-rm -f *.o mirrorfs

%.o: %.cc
	$(CXX) -std=c++0x $(CXXFLAGS) $^ -c -o $@

mirrorfs: mirrorfs.o utils/fs.o
	$(CXX) $(LDFLAGS) $^ -o $@
