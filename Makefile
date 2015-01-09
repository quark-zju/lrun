.PHONY: default install clean deb

default:
	cd src && rake

install:
	cd src && rake install
	cd utils/mirrorfs && make install

clean:
	cd src && rake clean

deb:
	debuild -i -us -uc -b
