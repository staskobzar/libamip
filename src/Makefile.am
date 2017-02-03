lib_LIBRARIES = libamip.a
libamip_a_SOURCES = amip.c amip.h

amip.c: amip.re
	re2c -o $@ $^
