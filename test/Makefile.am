if HAVE_CMOCKA
  TESTS = ami_msg_create_test ami_msg_parse_test
  check_PROGRAMS = ami_msg_parse_test ami_msg_create_test

  ami_msg_parse_test_SOURCES = ami_msg_parse_test.c
  ami_msg_parse_test_CFLAGS = @CMOCKA_CFLAGS@ -I$(top_builddir)/src
  ami_msg_parse_test_LDADD = -L$(top_builddir)/src -lamip @CMOCKA_LIBS@

  ami_msg_create_test_SOURCES = ami_msg_create_test.c
  ami_msg_create_test_CFLAGS = @CMOCKA_CFLAGS@ -I$(top_builddir)/src
  ami_msg_create_test_LDADD = -L$(top_builddir)/src -lamip @CMOCKA_LIBS@
endif
