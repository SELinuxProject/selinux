<!DOCTYPE style-sheet PUBLIC "-//James Clark//DTD DSSSL Style Sheet//EN" [
<!ENTITY docbook.dsl PUBLIC "-//Norman Walsh//DOCUMENT DocBook Print Stylesheet//EN" "/usr/share/sgml/docbook/dsssl-stylesheets-1.59/print/docbook.dsl" CDATA DSSSL>
]>

<style-sheet>
<style-specification id="print" use="docbook">
<style-specification-body>

(define %two-side% #f)
(define %section-autolabel% #t)
(define %generate-article-toc% #t)
(define %generate-article-titlepage% #t)

(define (article-titlepage-recto-elements)
  (list (normalize "title")
	(normalize "subtitle")
	(normalize "graphic")
	(normalize "corpauthor")
	(normalize "authorgroup")
	(normalize "author")
	(normalize "editor")
	(normalize "copyright")
	(normalize "contractnum")
	(normalize "contractsponsor")
	(normalize "productnumber")
	(normalize "isbn")
	(normalize "pubdate")
	(normalize "pubsnumber")
	(normalize "revhistory")
	(normalize "abstract")
	(normalize "legalnotice")))

(define (toc-depth nd) 2)


</style-specification-body>
</style-specification>

<external-specification id="docbook" document="docbook.dsl">

</style-sheet>
