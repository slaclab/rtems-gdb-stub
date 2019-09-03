#
#  Makefile.leaf,v 1.7 2002/07/22 22:56:09 joel Exp
#
# Templates/Makefile.leaf
# 	Template leaf node Makefile
#

#point to cexp source directory (only needed if USE_CEXP=yes)
#i.e., where the cexpmodP.h header can be found
CEXP_SOURCE_PATH=../cexp

#must be lower-case 'yes' (no quotes) to enable
USE_CEXP=yes
#must be lower-case 'yes' (no quotes) to enable
USE_LIBBSPEXT=no

# C source names, if any, go here -- minus the .c
C_PIECES_CEXP_yes = rtems-stub.modini
C_PIECES=rtems-stub $(STUB_$(RTEMS_CPU)) $(C_PIECES_CEXP_$(USE_CEXP))
C_FILES=$(C_PIECES:%=%.c)
C_O_FILES=$(C_PIECES:%=${ARCH}/%.o)

# C++ source names, if any, go here -- minus the .cc
CC_PIECES=
CC_FILES=$(CC_PIECES:%=%.cc)
CC_O_FILES=$(CC_PIECES:%=${ARCH}/%.o)

STUB_powerpc=rtems-gdb-stub-ppc-shared
STUB_i386   =rtems-gdb-stub-i386
STUB_m68k   =rtems-gdb-stub-m68k

S_PIECES_m68k=m68k-stackops

H_FILES=

# Assembly source names, if any, go here -- minus the .S
S_PIECES=$(S_PIECES_$(RTEMS_CPU))
S_FILES=$(S_PIECES:%=%.S)
S_O_FILES=$(S_FILES:%.S=${ARCH}/%.o)

SRCS=$(C_FILES) $(CC_FILES) $(H_FILES) $(S_FILES)
OBJS=$(C_O_FILES) $(CC_O_FILES) $(S_O_FILES)

# If your PGMS target has the '.exe' extension, a statically
# linked application is generated.
# If it has a '.obj' extension, a loadable module is built.

ifeq ($(USE_CEXP),yes)
PGMS=${ARCH}/rtems-gdb-stub.obj
endif
LIBNAME=librtems-gdb-stub.a
LIB=$(ARCH)/$(LIBNAME)

#  List of RTEMS Classic API Managers to be included in the application
#  goes here. Use:
#     MANAGERS=all
# to include all RTEMS Classic API Managers in the application or
# something like this to include a specific set of managers.
#     MANAGERS=io event message rate_monotonic semaphore timer
#
# UNUSED for loadable modules
MANAGERS=all

ifndef RTEMS_MAKEFILE_PATH
$(error you need to set the RTEMS_MAKEFILE_PATH environment variable)
endif

include $(RTEMS_MAKEFILE_PATH)/Makefile.inc

include $(RTEMS_CUSTOM)
include $(RTEMS_ROOT)/make/lib.cfg

#
# (OPTIONAL) Add local stuff here using +=
#
ifeq ($(USE_LIBBSPEXT),yes)
DEFINES  += -DHAVE_LIBBSPEXT
endif
ifeq ($(USE_CEXP),yes)
DEFINES  += -DHAVE_CEXP
CPPFLAGS += -I$(CEXP_SOURCE_PATH)
HCHECK    = $(CEXP_SOURCE_PATH)/cexpmodP.h
endif
DEFINES  += -DPACKAGE_VERSION=$(shell git describe --always --dirty)

CFLAGS   +=

#
# CFLAGS_DEBUG_V are used when the `make debug' target is built.
# To link your application with the non-optimized RTEMS routines,
# uncomment the following line:
# CFLAGS_DEBUG_V += -qrtems_debug
#

LD_PATHS  += 
LD_LIBS   += 
LDFLAGS   +=

#
# Add your list of files to delete here.  The config files
#  already know how to delete some stuff, so you may want
#  to just run 'make clean' first to see what gets missed.
#  'make clobber' already includes 'make clean'
#

CLEAN_ADDITIONS += *.out *.toc *.aux *.log html
CLOBBER_ADDITIONS += *.pdf

all:	${HCHECK} ${ARCH} $(SRCS) $(PGMS) $(LIB)

#How to make a relocatable object
$(filter %.obj, $(PGMS)): ${OBJS}
	$(make-obj)

#How to make an executable (statically linked)
$(filter %.exe,$(PGMS)): ${LINK_FILES}
	$(make-exe)
ifdef ELFEXT
ifdef XSYMS
	$(XSYMS) $(@:%.exe=%.$(ELFEXT)) $(@:%.exe=%.sym)
endif
endif

# doesn't work if we define this just after OBJS= :-(
# must be after inclusion of RTEMS_CUSTOM
$(LIB): OBJS:=$(filter-out %.modini.o,$(OBJS))

$(LIB): $(OBJS)
	$(make-library)


ifndef RTEMS_SITE_INSTALLDIR
RTEMS_SITE_INSTALLDIR = $(PROJECT_RELEASE)
endif

ifndef RTEMS_SITE_DOCDIR
RTEMS_SITE_DOCDIR = $(RTEMS_SITE_INSTALLDIR)
endif

ifndef make-obj
define make-obj
	$(make-rel) $(LINK_LIBS)
endef
endif

${RTEMS_SITE_INSTALLDIR}/include \
${RTEMS_SITE_INSTALLDIR}/lib \
${RTEMS_SITE_INSTALLDIR}/bin \
${RTEMS_SITE_INSTALLDIR}/$(RTEMS_BSP)/include \
${RTEMS_SITE_INSTALLDIR}/$(RTEMS_BSP)/lib \
${RTEMS_SITE_INSTALLDIR}/$(RTEMS_BSP)/bin :
	test -d $@ || mkdir -p $@

# Install the program(s), appending _g or _p as appropriate.
# for include files, just use $(INSTALL_CHANGE)
#
# NOTES:
#  - BSP specific applications, headers etc. should be installed to 
#          $RTEMS_SITE_INSTALLDIR)/$(RTEMS_BSP)/bin
#
#  - Some BSPs might generate bootable executables in yet another
#    format (such as .srec) and you might need to extend the rule
#    below so the essential files get installed. YMMV.
install:  all $(RTEMS_SITE_INSTALLDIR)/bin $(RTEMS_SITE_INSTALLDIR)/lib
	$(INSTALL_VARIANT) -m 555 ${PGMS} ${PGMS:%.exe=%.bin} ${PGMS:%.exe=%.sym} ${RTEMS_SITE_INSTALLDIR}/bin
	$(INSTALL_VARIANT) -m 644 ${LIB} ${RTEMS_SITE_INSTALLDIR}/lib

doc: rtems-gdb-stub.pdf

docinst: $(RTEMS_SITE_DOCDIR)/gdb/rtems-gdb-stub.pdf $(RTEMS_SITE_DOCDIR)/html/rtems-gdb-stub/index.html

%.pdf: %.tex
	pdflatex $^	
	pdflatex $^	
	pdflatex $^	

$(RTEMS_SITE_DOCDIR)/gdb/rtems-gdb-stub.pdf: rtems-gdb-stub.pdf
	@mkdir -p $(RTEMS_SITE_DOCDIR)/gdb
	$(INSTALL_CHANGE) $^ $@

define make-html
	@mkdir -p $(shell dirname $@)
	latex2html -split 4 -dir $(shell dirname $@) rtems-gdb-stub
endef

$(RTEMS_SITE_DOCDIR)/html/rtems-gdb-stub/index.html: rtems-gdb-stub.tex
	$(make-html)

html/index.html: rtems-gdb-stub.tex
	$(make-html)

REVISION=$(shell git describe --always --dirty)

tar: doc html/index.html
	@$(make-tar)

ifdef HCHECK
$(HCHECK):
	$(error "$@" not found! Edit the Makefile and fix CEXP_SOURCE_PATH)
endif
