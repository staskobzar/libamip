lib_LIBRARIES = libamip.a
libamip_a_SOURCES = amip.c parse_prompt.c parse_stanza.c parse_pack.c amip.h

parse_prompt.c: parse_prompt.re
	re2c -c -o $@ $^

parse_stanza.c: parse_stanza.re
	re2c -o $@ $^

parse_pack.c: parse_pack.re
	re2c -c -o $@ $^

