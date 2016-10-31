SHAREDIR ?= $(DESTDIR)/var/lib/sepolgen

all:

install: all
	-mkdir -p $(SHAREDIR)
	install -m 644 perm_map $(SHAREDIR)

clean:
	rm -f *~