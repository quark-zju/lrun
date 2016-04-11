.PHONY: default install clean deb

default:
	cd src && rake
	make -C tools/mirrorfs
	make -C tools/netns-empty

install:
	cd src && rake install
	make install -C tools/mirrorfs
	make install -C tools/netns-empty

clean:
	cd src && rake clean

deb:
	debuild -i -us -uc -b
