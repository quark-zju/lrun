BINARIES=lrun
OBJECTS=lrun.o strconv.o fs.o cgroup.o macros.o
CXXFLAGS=-g -O2 -std=c++0x -Wall
LDFLAGS=
LD=g++
PREFIX?=/usr/local
INSTALL?=/usr/bin/env install -c -D

.PHONY: all clean install

all: $(BINARIES)

lrun: $(OBJECTS)
	$(LD) -o $@ $(LDFLAGS) $^

clean:
	-rm -f $(OBJECTS) $(BINARIES)

$(OBJECTS): %.o: %.cc
	$(CXX) $(CXXFLAGS) $^ -c -o $@

install: lrun
	$(INSTALL) -m4555 -oroot -groot -s $< $(DESTDIR)$(PREFIX)/bin/lrun
