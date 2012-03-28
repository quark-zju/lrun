BINARIES=lrun
CXXFLAGS=-O2 -std=c++0x -Wall
PREFIX?=/usr/local
DEST=$(PREFIX)/bin/lrun

.PHONY: all clean install

all: $(BINARIES)

lrun: lrun.o strconv.o fs.o cgroup.o

clean:
	-rm -f *.o $(BINARIES)

.o.cc:

.o:
	$(CXX) $(LDFLAGS) $^ -o $@

install: lrun
	install -oroot -s -m6755 $^ $(DEST)
