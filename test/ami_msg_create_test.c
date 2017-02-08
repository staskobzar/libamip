#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdio.h>
#include "amip.h"

static int setup_pack(void **state)
{
  *state = (AMIPacket*) XMALLOC(sizeof(AMIPacket));
  return 0;
}

static int teardown_pack(void **state)
{
  amipack_destroy (*state);
  return 0;
}

static void create_pack_with_no_header (void **state)
{
  struct str pack_str;
  AMIPacket *pack = *state;

  amipack_init (pack, AMI_ACTION);
  assert_int_equal (pack->size, 0);
  amipack_to_str(pack, &pack_str);
  assert_null (pack_str.buf);
  assert_int_equal (pack_str.len, 0);
}

static void create_pack_with_single_header (void **state)
{
  struct str pack_str;
  AMIPacket *pack = *state;

  amipack_init (pack, AMI_ACTION);
  amipack_append (pack, Action, "CoreStatus");

  assert_int_equal (pack->size, 1);

  amipack_to_str(pack, &pack_str);
  assert_string_equal (pack_str.buf, "Action: CoreStatus\r\n\r\n");

  assert_int_equal(pack_str.len, pack->length + 2); // + stanza CRLF
}

static void create_pack_with_multi_headers (void **state)
{
  struct str pack_str;
  AMIPacket *pack = *state;

  amipack_init (pack, AMI_ACTION);
  amipack_append (pack, Action, "ExtensionState");
  amipack_append (pack, Exten, "5555");
  amipack_append (pack, Context, "inbound-local");

  assert_int_equal (pack->size, 3);

  amipack_to_str(pack, &pack_str);
  assert_string_equal (pack_str.buf, "Action: ExtensionState\r\nExten: 5555\r\nContext: inbound-local\r\n\r\n");

  assert_int_equal(pack_str.len, pack->length + 2); // + stanza CRLF
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup_teardown (create_pack_with_no_header, setup_pack, teardown_pack),
    cmocka_unit_test_setup_teardown (create_pack_with_single_header, setup_pack, teardown_pack),
    cmocka_unit_test_setup_teardown (create_pack_with_multi_headers, setup_pack, teardown_pack),
  };
  return cmocka_run_group_tests_name("Create AMI package tests.", tests, NULL, NULL);
}
