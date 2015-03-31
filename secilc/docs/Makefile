HTMLDIR ?= ./html
PDFDIR ?= ./pdf

# The CIL Reference Guide first part
CIL_REF_GUIDE = CIL_Reference_Guide.xml
# All the docbook files that make up the guide:
FILE_LIST ?= $(CIL_REF_GUIDE) $(wildcard cil*.xml)
# xmlto generates a *.proc file that can be removed.
PROC_FILE = CIL_Reference_Guide.proc

# look for xmlto and dblatex packages
XMLTO = $(shell which xmlto 2> /dev/null | grep / | head -n1)
DBLATEX = $(shell which dblatex 2> /dev/null | grep / | head -n1)

# If no xmlto then exit as cannot proceed.
ifeq ($(XMLTO),)
$(error xmlto package not found - install package.)
endif

all: html pdf

html: $(FILE_LIST)
	$(XMLTO) html $(CIL_REF_GUIDE)
	@mkdir -p $(HTMLDIR)
	@for m in *.html; do if [ -f $$m ]; then mv $$m $(HTMLDIR); fi; done
	@rm -f $(PROC_FILE)


pdf: $(FILE_LIST)
# Check if dblatex is available
ifeq ($(DBLATEX),)
	$(error dblatex package not found - install package for a pdf document.)
endif
	$(XMLTO) --with-dblatex pdf  $(CIL_REF_GUIDE)
	@mkdir -p $(PDFDIR)
	@for m in *.pdf; do if [ -f $$m ]; then mv $$m $(PDFDIR); fi; done
	@rm -f $(PROC_FILE)

clean:
	@rm -rf html/
	@rm -rf pdf/
