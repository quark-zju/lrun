BINARIES=fs_unit_test cgroup_unit_test strconv_unit_test
CXXFLAGS=-I../src -g -std=c++0x -Wall

.PHONY: all clean

all: $(BINARIES)

fs_unit_test: fs_unit_test.o ../src/fs.o test.o

cgroup_unit_test: cgroup_unit_test.o ../src/cgroup.o ../src/strconv.o ../src/fs.o test.o

strconv_unit_test: strconv_unit_test.o ../src/strconv.o test.o

.o.cc:

.o:
	$(CXX) $(LDFLAGS) $^ -o $@

clean:
	-rm -f *.o $(BINARIES)
