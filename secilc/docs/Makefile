CWD = $(shell pwd)
HTMLDIR = $(CWD)/html
PDFDIR = $(CWD)/pdf
TMPDIR = $(CWD)/tmp
TESTDIR = $(CWD)/../test

# All the markdown files that make up the guide:
FILE_LIST ?= cil_introduction.md \
	cil_reference_guide.md \
	cil_access_vector_rules.md \
	cil_call_macro_statements.md \
	cil_class_and_permission_statements.md \
	cil_conditional_statements.md \
	cil_constraint_statements.md \
	cil_container_statements.md \
	cil_context_statement.md \
	cil_default_object_statements.md \
	cil_file_labeling_statements.md \
	cil_mls_labeling_statements.md \
	cil_network_labeling_statements.md \
	cil_policy_config_statements.md \
	cil_role_statements.md \
	cil_sid_statements.md \
	cil_type_statements.md \
	cil_user_statements.md \
	cil_infiniband_statements.md \
	cil_xen_statements.md

PANDOC_FILE_LIST = $(addprefix $(TMPDIR)/,$(FILE_LIST))

PANDOC_HIGHLIGHT_STYLE="theme.theme"

PDF_OUT=CIL_Reference_Guide.pdf
HTML_OUT=CIL_Reference_Guide.html
PANDOC = pandoc
SED ?= sed

OS := $(shell uname)
ifeq ($(OS), Darwin)
	SED := gsed
endif

all: html pdf

$(TMPDIR):
	mkdir -p $(TMPDIR)

$(TMPDIR)/%.md: %.md | $(TMPDIR)
	cp -f $< $(TMPDIR)/
	@# Substitute markdown links for conversion into PDF links
	$(SED) -i -re 's:(\[`[^`]*`\])\([^#]*([^\)]):\1\(\2:g' $@

$(TMPDIR)/policy.cil: $(TESTDIR)/policy.cil
	cp -f $< $@
	@# add a title for the TOC to policy.cil. This is needed to play nicely with the PDF conversion.
	$(SED) -i '1i Example Policy\n=========\n```secil' $@
	echo '```' >> $@

html: $(PANDOC_FILE_LIST) $(TMPDIR)/policy.cil secil.xml
	mkdir -p $(HTMLDIR)
	$(PANDOC) \
		--highlight-style=$(PANDOC_HIGHLIGHT_STYLE) \
		--syntax-definition=secil.xml \
		--standalone \
		--metadata title="CIL Reference Guide" \
		--metadata document-css=false \
		-t html \
		$(PANDOC_FILE_LIST) $(TMPDIR)/policy.cil \
		-o $(HTMLDIR)/$(HTML_OUT)

pdf: $(PANDOC_FILE_LIST) $(TMPDIR)/policy.cil secil.xml
	mkdir -p $(PDFDIR)
	$(PANDOC) \
		--highlight-style=$(PANDOC_HIGHLIGHT_STYLE) \
		--syntax-definition=secil.xml \
		--standalone \
		--toc \
		$(PANDOC_FILE_LIST) $(TMPDIR)/policy.cil \
		-o $(PDFDIR)/$(PDF_OUT)

clean:
	rm -rf $(HTMLDIR)
	rm -rf $(PDFDIR)
	rm -rf $(TMPDIR)
