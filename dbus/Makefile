PREFIX ?= /usr

all:

clean:

install:
	-mkdir -p $(DESTDIR)/etc/dbus-1/system.d/
	install -m 644 org.selinux.conf $(DESTDIR)/etc/dbus-1/system.d/
	-mkdir -p $(DESTDIR)$(PREFIX)/share/dbus-1/system-services
	install -m 644 org.selinux.service $(DESTDIR)$(PREFIX)/share/dbus-1/system-services
	-mkdir -p $(DESTDIR)$(PREFIX)/share/polkit-1/actions/
	install -m 644 org.selinux.policy $(DESTDIR)$(PREFIX)/share/polkit-1/actions/
	-mkdir -p $(DESTDIR)$(PREFIX)/share/system-config-selinux
	install -m 755 selinux_server.py $(DESTDIR)$(PREFIX)/share/system-config-selinux

relabel:

test:
