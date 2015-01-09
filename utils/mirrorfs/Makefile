CXXFLAGS=-O0 -g -std=c++0x -Wall

.PHONY: all clean

all: mirrorfs

clean:
	-rm -f *.o mirrorfs

%.o: %.cc
	$(CXX) $(CXXFLAGS) $^ -c -o $@

mirrorfs: mirrorfs.o utils/fs.o
	$(CXX) $(LDFLAGS) $^ -o $@
