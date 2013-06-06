CC=$(CXX)
PREFIX ?= /usr/local

libexecwhitelist.so: libexecwhitelist.c
	gcc $^ -fPIC -ldl -shared -lseccomp -o $@

clean:
	rm -f libexecwhitelist.so

install: libexecwhitelist.so
	install -m555 -oroot -groot -s libexecwhitelist.so $(PREFIX)/lib/libexecwhitelist.so
