PREFIX ?= /usr
PYTHON ?= python3
PYTHONLIBDIR ?= $(shell $(PYTHON) -c "import sysconfig; print(sysconfig.get_path('purelib', vars={'platbase': '$(PREFIX)', 'base': '$(PREFIX)'}))")
PACKAGEDIR ?= /$(PYTHONLIBDIR)/sepolgen

all:

install: all
	-mkdir -p $(DESTDIR)$(PACKAGEDIR)
	install -m 644 *.py $(DESTDIR)$(PACKAGEDIR)

clean:
	rm -f parser.out parsetab.py
	rm -f *~ *.pyc
	rm -rf __pycache__
