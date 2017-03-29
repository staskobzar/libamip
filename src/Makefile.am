lib_LIBRARIES = libamip.a
libamip_a_SOURCES = amip.c parse_prompt.c parse_pack.c amip.h
nobase_include_HEADERS = amip.h

parse_prompt.c: parse_prompt.re
	re2c --no-generation-date -c -o $@ $^

parse_pack.c: parse_pack.re
	re2c --no-generation-date -c -o $@ $^

