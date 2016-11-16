all: 
	$(MAKE) -C src 
	$(MAKE) -C utils

install: 
	$(MAKE) -C src install
#	$(MAKE) -C utils install
	$(MAKE) -C man install

clean:
	rm -f *~ \#*
	$(MAKE) -C src clean
	$(MAKE) -C utils clean
	$(MAKE) -C man clean

relabel:

test:
