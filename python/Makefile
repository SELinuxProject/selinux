SUBDIRS = sepolicy audit2allow semanage sepolgen chcat po

all install relabel clean indent test:
	@for subdir in $(SUBDIRS); do \
		(cd $$subdir && $(MAKE) $@) || exit 1; \
	done
