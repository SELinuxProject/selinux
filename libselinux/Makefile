all: 
	$(MAKE) -C src 
	$(MAKE) -C utils

pywrap: 
	$(MAKE) -C src pywrap

install: 
	$(MAKE) -C include install
	$(MAKE) -C src install
	$(MAKE) -C utils install
	$(MAKE) -C man install

install-pywrap: 
	$(MAKE) -C src install-pywrap 

relabel: 
	$(MAKE) -C src relabel

clean distclean:
	$(MAKE) -C src $@
	$(MAKE) -C utils clean

indent:
	$(MAKE) -C src $@
	$(MAKE) -C utils $@
	$(MAKE) -C include $@

test:
