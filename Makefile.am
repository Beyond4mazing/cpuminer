
if WANT_JANSSON
JANSSON_INCLUDES= -I$(top_srcdir)/compat/jansson
else
JANSSON_INCLUDES=
endif

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST	= example-cfg.json nomacro.pl

SUBDIRS		= compat

INCLUDES	= $(PTHREAD_FLAGS) -fno-strict-aliasing $(JANSSON_INCLUDES)

bin_PROGRAMS	= minerd

minerd_SOURCES	= elist.h miner.h compat.h \
		  cpu-miner.c util.c \
		  x2/sha2.c x2/sha2-arm.S x2/sha2-x86.S x2/sha2-x64.S \
		  x2/scrypt.c x2/scrypt-arm.S x2/scrypt-x86.S x2/scrypt-x64.S \
		  sph/aes_helper.c sph/luffa.c sph/shavite.c sph/cubehash.c x5/vect128/nist.c x5/vect128/vector.c \
		  sph/echo.c sph/blake.c x5/echo512/ccalik/aesni/hash.c \
		  sph/groestl.c sph/keccak.c sph/simd.c sph/bmw.c sph/jh.c sph/skein.c x11evo.c
minerd_LDFLAGS	= $(PTHREAD_FLAGS)
minerd_LDADD	= @LIBCURL@ @JANSSON_LIBS@ @PTHREAD_LIBS@ @WS2_LIBS@
minerd_CPPFLAGS = @LIBCURL_CPPFLAGS@

