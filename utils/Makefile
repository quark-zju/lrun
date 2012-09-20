.PHONY: all clean test install

PREFIX?=/usr/local
INSTALL?=/usr/bin/env install -c -D

all: ol

ol: ol.c
	$(CC) -O2 -fno-math-errno -Wall $^ -o $@
	-strip -R .note -R .comment -R .eh_frame -R .eh_frame_hdr -s $@

clean:
	-rm -f ol

install: ol
	$(INSTALL) -m555 -oroot -groot -s $< $(DESTDIR)$(PREFIX)/bin/ol

test:
	echo 'hello' | ./ol 6 &>/dev/null
	! (echo 'hello' | ./ol 4) &>/dev/null
	# also try:
	#   cat /dev/zero | pv > /dev/null
	#   pkill pv
	# and
	#   cat /dev/zero | ./ol | pv > /dev/null
	#   pkill pv # cat still runs
