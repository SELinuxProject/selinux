PKG_CONFIG ?= pkg-config
PCRE_MODULE := libpcre2-8
PCRE_CFLAGS := $(shell $(PKG_CONFIG) --cflags $(PCRE_MODULE)) -DPCRE2_CODE_UNIT_WIDTH=8
PCRE_LDLIBS := $(shell $(PKG_CONFIG) --libs $(PCRE_MODULE))
export PCRE_MODULE PCRE_CFLAGS PCRE_LDLIBS

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
