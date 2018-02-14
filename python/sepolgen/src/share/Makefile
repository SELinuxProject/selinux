SHAREDIR ?= /var/lib/sepolgen

all:

install: all
	-mkdir -p $(DESTDIR)$(SHAREDIR)
	install -m 644 perm_map $(DESTDIR)$(SHAREDIR)

clean:
	rm -f *~
