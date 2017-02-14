lib_LIBRARIES = libamip.a
libamip_a_SOURCES = amip.c amip_parse.c amip.h

amip_parse.c: amip_parse.re
	re2c -c -o amip_parse.c amip_parse.re
