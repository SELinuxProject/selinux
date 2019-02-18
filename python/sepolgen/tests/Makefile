PYTHON ?= python3

clean:
	rm -f *~ *.pyc
	rm -f parser.out parsetab.py
	rm -f out.txt
	rm -f module_compile_test.fc
	rm -f module_compile_test.if
	rm -f module_compile_test.pp
	rm -f output
	rm -rf __pycache__ tmp

test:
	$(PYTHON) run-tests.py
