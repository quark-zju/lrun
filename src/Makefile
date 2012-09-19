BINARIES=lrun
CXXFLAGS=-O2 -std=c++0x -Wall
LDFLAGS=
LD=g++
PREFIX?=/usr/local
INSTALL?=/usr/bin/env install -c -D

.PHONY: all clean install

all: $(BINARIES)

lrun: lrun.o strconv.o fs.o cgroup.o
	$(LD) -o $@ $(LDFLAGS) $^

clean:
	-rm -f *.o $(BINARIES)

.o.cc:

.o:
	$(CXX) $(LDFLAGS) $^ -o $@

install: lrun
	$(INSTALL) -m4555 -oroot -groot -s $< $(DESTDIR)$(PREFIX)/bin/lrun
