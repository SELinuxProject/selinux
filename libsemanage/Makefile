all: 
	$(MAKE) -C src all

swigify:
	$(MAKE) -C src swigify

pywrap: 
	$(MAKE) -C src pywrap

install: 
	$(MAKE) -C include install
	$(MAKE) -C src install
	$(MAKE) -C man install

install-pywrap: 
	$(MAKE) -C src install-pywrap

relabel:
	$(MAKE) -C src relabel

clean distclean:
	$(MAKE) -C src $@
	$(MAKE) -C tests $@

indent:
	$(MAKE) -C src $@
	$(MAKE) -C include $@

test: all
	$(MAKE) -C tests test
