all:
	$(MAKE) -C src all

swigify:
	$(MAKE) -C src swigify

pywrap:
	$(MAKE) -C src pywrap

rubywrap:
	$(MAKE) -C src rubywrap

install:
	$(MAKE) -C include install
	$(MAKE) -C src install
	$(MAKE) -C man install
	$(MAKE) -C utils install

install-pywrap:
	$(MAKE) -C src install-pywrap

install-rubywrap:
	$(MAKE) -C src install-rubywrap

relabel:
	$(MAKE) -C src relabel

clean distclean:
	$(MAKE) -C src $@
	$(MAKE) -C tests $@

test: all
	$(MAKE) -C tests test
