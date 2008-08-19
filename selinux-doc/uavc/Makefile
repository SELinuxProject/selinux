TOP     := main.sgml
ALL     := $(wildcard *.sgml)

PS	:=	$(patsubst %.sgml, %.ps, $(TOP))
PDF	:=	$(patsubst %.sgml, %.pdf, $(TOP))
HTML    :=      $(patsubst %.sgml, %, $(TOP))
DVI	:=	$(patsubst %.sgml, %.dvi, $(TOP))
AUX	:=	$(patsubst %.sgml, %.aux, $(TOP))
TEX	:=	$(patsubst %.sgml, %.tex, $(TOP))
LOG	:=	$(patsubst %.sgml, %.log, $(TOP))
OUT	:=	$(patsubst %.sgml, %.out, $(TOP))

all: $(PS) $(HTML) $(PDF)

$(PS): $(ALL) custom.dsl
	jw -f docbook -d custom.dsl -b ps $(TOP)

$(PDF): $(ALL) custom.dsl
	jw -f docbook -d custom.dsl -b pdf $(TOP)

$(HTML): $(ALL)
	-$(RM) -r $@
	db2html $(TOP)
	if [ ! -z "$(JPG-$@)" ]; then cp $(JPG-$@) $@; fi

clean:
	-$(RM) core *~
	-$(RM) $(DVI) $(AUX) $(TEX) $(LOG) $(OUT)

mrproper: clean
	-$(RM) $(PS) $(PDF)
	-$(RM) -r $(HTML)
