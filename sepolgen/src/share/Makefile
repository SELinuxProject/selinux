SHAREDIR ?= $(DESTDIR)/var/lib/sepolgen

install:
	-mkdir -p $(SHAREDIR)
	install -m 644 perm_map $(SHAREDIR)

clean:
	rm -f *~