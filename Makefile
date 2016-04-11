.PHONY: default install clean deb

default:
	cd src && rake
	cd tools/mirrorfs && make

install:
	cd src && rake install
	cd tools/mirrorfs && make install

clean:
	cd src && rake clean

deb:
	debuild -i -us -uc -b
