BINARIES=fs_unit_test cgroup_unit_test strconv_unit_test
CXXFLAGS=-I../src -g -std=c++0x -Wall `pkg-config --cflags --silence-errors libseccomp`
LDFLAGS=`pkg-config --libs --silence-errors libseccomp`
LD=g++

.PHONY: all clean

all: $(BINARIES)

fs_unit_test:  test.o ../src/fs.o ../src/common.o fs_unit_test.o
	$(LD) $(LDFLAGS) $^ -o $@

cgroup_unit_test: test.o ../src/cgroup.o ../src/strconv.o ../src/fs.o ../src/common.o ../src/seccomp.o cgroup_unit_test.o
	$(LD) $(LDFLAGS) $^ -o $@

strconv_unit_test: test.o ../src/strconv.o ../src/common.o strconv_unit_test.o
	$(LD) $(LDFLAGS) $^ -o $@

.o.cc:

.o:
	$(CXX) $(LDFLAGS) $^ -o $@

clean:
	-rm -f *.o $(BINARIES)
