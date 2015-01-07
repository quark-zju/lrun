BINARIES=fs_unit_test cgroup_unit_test strconv_unit_test integration_test
CXXFLAGS=-I../src -g -std=c++0x -Wall
LD_SECCOMP_FLAGS=`pkg-config --libs --silence-errors libseccomp`
LD=g++

.PHONY: all clean

all: $(BINARIES)

fs_unit_test:  test.o ../src/utils/fs.o fs_unit_test.o
	$(LD) $(LDFLAGS) $^ -o $@

cgroup_unit_test: test.o ../src/cgroup.o ../src/utils/strconv.o ../src/utils/fs.o ../src/utils/now.o ../src/utils/log.o ../src/seccomp.o cgroup_unit_test.o
	$(LD) -pthread $(LDFLAGS) $^ $(LD_SECCOMP_FLAGS) -o $@

strconv_unit_test: test.o ../src/utils/strconv.o strconv_unit_test.o
	$(LD) $(LDFLAGS) $^ -o $@

integration_test: test.o integration_test.o
	$(LD) $(LDFLAGS) $^ -o $@

%.o: %.cc
	$(CXX) $(CXXFLAGS) $^ -c -o $@

clean:
	-rm -f *.o $(BINARIES)
