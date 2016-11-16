all:

clean:

install:
	-mkdir -p $(DESTDIR)/etc/dbus-1/system.d/
	install -m 644 org.selinux.conf $(DESTDIR)/etc/dbus-1/system.d/
	-mkdir -p $(DESTDIR)/usr/share/dbus-1/system-services
	install -m 644 org.selinux.service $(DESTDIR)/usr/share/dbus-1/system-services
	-mkdir -p $(DESTDIR)/usr/share/polkit-1/actions/
	install -m 644 org.selinux.policy $(DESTDIR)/usr/share/polkit-1/actions/
	-mkdir -p $(DESTDIR)/usr/share/system-config-selinux
	install -m 755 selinux_server.py $(DESTDIR)/usr/share/system-config-selinux

relabel:

test:
