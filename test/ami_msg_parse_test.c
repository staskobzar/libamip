#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "amip.h"

static void parse_prompt_header_11 (void **state)
{
  (void)*state;
  const char *str = "Asterisk Call Manager/1.1\r\n";
  AMIVer ver;
  int ret = amiparse_prompt (str, &ver);
  assert_int_equal (RV_SUCCESS, ret);
  assert_int_equal (1, ver.major);
  assert_int_equal (1, ver.minor);
  assert_int_equal (0, ver.patch);
}

static void parse_prompt_header_280 (void **state)
{
  (void)*state;
  const char *str = "Asterisk Call Manager/2.8.4\r\n";
  AMIVer ver;
  int ret = amiparse_prompt (str, &ver);
  assert_int_equal (RV_SUCCESS, ret);
  assert_int_equal (2, ver.major);
  assert_int_equal (8, ver.minor);
  assert_int_equal (4, ver.patch);
}

static void parse_not_prompt_pack (void **state)
{
  (void)*state;
  const char *str = "Response: Success\r\n";
  AMIVer ver;
  int ret = amiparse_prompt (str, &ver);
  assert_int_equal (RV_FAIL, ret);
  assert_int_equal (0, ver.major);
  assert_int_equal (0, ver.minor);
  assert_int_equal (0, ver.patch);
}

static void parse_action_one_header (void **state)
{
  (void)*state;
  const char *str = "Action: CoreStatus\r\n\r\n";
  AMIPacket pack;
  enum pack_type ret = amiparse_pack (str, &pack);
  assert_int_equal (AMI_ACTION, ret);
  assert_int_equal (AMI_ACTION, pack.type);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test (parse_prompt_header_11),
    cmocka_unit_test (parse_prompt_header_280),
    cmocka_unit_test (parse_not_prompt_pack),
    cmocka_unit_test (parse_action_one_header),
  };
  return cmocka_run_group_tests_name("Parse AMI package tests.", tests, NULL, NULL);
}
