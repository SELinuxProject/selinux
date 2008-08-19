DISABLE_AVC ?= n
DISABLE_SETRANS ?= n
DISABLE_RPM ?= n
DISABLE_BOOL ?= n
ifeq ($(EMBEDDED),y)
	override DISABLE_AVC=y
	override DISABLE_SETRANS=y
	override DISABLE_RPM=y
	override DISABLE_BOOL=y
endif
ifeq ($(DISABLE_AVC),y)
	EMFLAGS+= -DDISABLE_AVC
endif
ifeq ($(DISABLE_BOOL),y)
	EMFLAGS+= -DDISABLE_BOOL
endif
ifeq ($(DISABLE_SETRANS),y)
	EMFLAGS+= -DDISABLE_SETRANS
endif
export DISABLE_AVC DISABLE_SETRANS DISABLE_RPM DISABLE_BOOL EMFLAGS

all: 
	$(MAKE) -C src 
	$(MAKE) -C utils

swigify: all
	$(MAKE) -C src swigify

pywrap: 
	$(MAKE) -C src pywrap

rubywrap: 
	$(MAKE) -C src rubywrap

install: 
	$(MAKE) -C include install
	$(MAKE) -C src install
	$(MAKE) -C utils install
	$(MAKE) -C man install

install-pywrap: 
	$(MAKE) -C src install-pywrap 

install-rubywrap: 
	$(MAKE) -C src install-rubywrap 

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
