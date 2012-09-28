BINARIES=lrun
OBJECTS=lrun.o strconv.o fs.o cgroup.o macros.o seccomp.o
LIBSECCOMP_VERSION_MAJOR:=$(shell pkg-config --modversion libseccomp | sed 's/\..*//')
PKG_NAMES=libseccomp
PKG_CFLAGS:=$(shell pkg-config --cflags $(PKG_NAMES))
PKG_LDFLAGS:=$(shell pkg-config --libs $(PKG_NAMES))
CXXFLAGS=-O2 -std=c++0x -Wall -DLIBSECCOMP_VERSION_MAJOR=$(LIBSECCOMP_VERSION_MAJOR) $(PKG_CFLAGS)
LDFLAGS=$(PKG_LDFLAGS)
LD=g++
PREFIX?=/usr/local
INSTALL?=/usr/bin/env install -c -D

.PHONY: all clean install

all: $(BINARIES)

lrun: $(OBJECTS)
	$(LD) $(LDFLAGS) $^ -o $@

clean:
	-rm -f $(OBJECTS) $(BINARIES)

$(OBJECTS): %.o: %.cc
	$(CXX) $(CXXFLAGS) $^ -c -o $@

install: lrun
	$(INSTALL) -m4555 -oroot -groot -s $< $(DESTDIR)$(PREFIX)/bin/lrun
