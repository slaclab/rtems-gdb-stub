#  $Id$
AUTOMAKE_OPTIONS=foreign

include $(top_srcdir)/rtems-pre.am

EXEEXT=$(OBJEXEEXT)

STUB_powerpc                      = rtems-gdb-stub-ppc-shared.c rtems-gdb-stub-ppc-shared.h
STUB_i386                         = rtems-gdb-stub-i386.c rtems-gdb-stub-i386.h
STUB_m68k                         = rtems-gdb-stub-m68k.c m68k-stackops.S rtems-gdb-stub-m68k.h

librtems_gdb_stub_a_SOURCES       = rtems-stub.c rtems-gdb-stubP.h cdll.h
EXTRA_librtems_gdb_stub_a_SOURCES = $(STUB_powerpc) $(STUB_i386) $(STUB_m68k)
librtems_gdb_stub_a_LIBADD        = $(filter %.o,$(STUB_@rtems_cpu@:%.c=%.o) $(STUB_@rtems_cpu@:%.S=%.o))
librtems_gdb_stub_a_DEPENDENCIES  = $(filter %.o,$(STUB_@rtems_cpu@:%.c=%.o) $(STUB_@rtems_cpu@:%.S=%.o))

# Use empty info_TEXINFOS so that PDF and html install rules are created
info_TEXINFOS                     =

lib_LIBRARIES                     = librtems-gdb-stub.a

include_HEADERS                   = rtems-gdb-stub.h

if HAVE_CEXP
bin_PROGRAMS                      = rtems-gdb-stub
rtems_gdb_stub_SOURCES            = rtems-stub.modini.c
rtems_gdb_stub_LDADD              = $(librtems_gdb_stub_a_OBJECTS)
rtems_gdb_stub_DEPENDENCIES       = $(librtems_gdb_stub_a_OBJECTS)

EXTRA_rtems_gdb_stub_SOURCES      = crc32.c switch_stack.c cdll-tst.c
EXTRA_rtems_gdb_stub_SOURCES     += $(EXTRA_librtems_gdb_stub_a_SOURCES)

rtems_gdb_stub_LDADD             += $(librtems_gdb_stub_a_LIBADD)
rtems_gdb_stub_DEPENDENCIES      += $(librtems_gdb_stub_a_DEPENDENCIES)

AM_CPPFLAGS                      += -I$(srcdir)/../cexp/
endif

clean-local:
	$(RM) *.out *.toc *.aux *.log
	$(RM) -r html

maintainer-clean-local:
	$(RM) *.pdf

include $(top_srcdir)/rtems.am

rtems_gdb_stub_LINK=$(OBJLINK)

PDFS=rtems-gdb-stub.pdf

EXTRA_DIST=$(PDFS)

pdf-local: rtems-gdb-stub.pdf

rtems-gdb-stub.pdf: rtems-gdb-stub.tex
	pdflatex $^
	pdflatex $^

define make-html
	@if test -d $(shell dirname $@) ; then : else mkdir -p $(shell dirname $@) fi
	latex2html -split 4 -dir $(shell dirname $@) rtems-gdb-stub
endef

html/index.html: rtems-gdb-stub.tex
	$(make-html)

HTMLS=$(wildcard html/*)

html-local: html/index.html
