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

static void parse_packet_stanza (void **state)
{
  (void)*state;
  int rv;
  const char *complete = "Action: CoreStatus\r\n\r\n";
  const char *uncomplete = "Action: CoreStatus\r\n";

  rv = amiparse_stanza (complete);
  assert_int_equal (RV_SUCCESS, rv);

  rv = amiparse_stanza (uncomplete);
  assert_int_equal (RV_FAIL, rv);
}

static void parse_action_one_header (void **state)
{
  (void)*state;
  AMIPacket *pack;
  int ret;
  struct str *hv; // header value
  const char *str = "Action: CoreStatus\r\n\r\n";

  ret = amiparse_stanza (str);
  assert_int_equal (RV_SUCCESS, ret);

  pack = amiparse_pack (str);
  assert_int_equal (AMI_ACTION, pack->type);
  assert_int_equal (pack->size, 1);
  hv = amiheader_value(pack, Action);
  assert_string_equal(hv->buf, "CoreStatus");
  amipack_destroy (pack);
}

static void parse_event_one_header (void **state)
{
  (void)*state;
  AMIPacket *pack;
  int ret;
  struct str *hv; // header value
  const char *str = "Event: FullyBooted\r\n\r\n";

  ret = amiparse_stanza (str);
  assert_int_equal (RV_SUCCESS, ret);

  pack = amiparse_pack (str);
  assert_int_equal (pack->type, AMI_EVENT);
  assert_int_equal (pack->size, 1);
  hv = amiheader_value(pack, Event);
  assert_string_equal(hv->buf, "FullyBooted");
  amipack_destroy (pack);
}

static void parse_response_one_header (void **state)
{
  (void)*state;
  AMIPacket *pack;
  int ret;
  struct str *hv; // header value
  const char *str = "Response: Success\r\n\r\n";

  ret = amiparse_stanza (str);
  assert_int_equal (RV_SUCCESS, ret);

  pack = amiparse_pack (str);
  assert_int_equal (pack->type, AMI_RESPONSE);
  assert_int_equal (pack->size, 1);
  hv = amiheader_value(pack, Response);
  assert_string_equal(hv->buf, "Success");
  amipack_destroy (pack);
}

static void parse_unknown_one_header (void **state)
{
  (void)*state;
  AMIPacket *pack;
  int ret;
  struct str *hv; // header value
  const char *str = "Unknown-Header_Name: Unknown AMI Packet\r\n\r\n";

  //ret = amiparse_stanza (str);
  //assert_int_equal (RV_SUCCESS, ret);

  //pack = amiparse_pack (str);
  //assert_non_null (pack);
  //assert_int_equal (pack->type, AMI_UNKNOWN);
  //assert_int_equal (pack->size, 1);
  //amipack_destroy (pack);
}

// TODO: invalid packet
// TODO: case insensative headers
// TODO: multi headers

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test (parse_prompt_header_11),
    cmocka_unit_test (parse_prompt_header_280),
    cmocka_unit_test (parse_not_prompt_pack),
    cmocka_unit_test (parse_packet_stanza),
    cmocka_unit_test (parse_action_one_header),
    cmocka_unit_test (parse_event_one_header),
    cmocka_unit_test (parse_response_one_header),
    cmocka_unit_test (parse_unknown_one_header),
  };
  return cmocka_run_group_tests_name("Parse AMI package tests.", tests, NULL, NULL);
}
