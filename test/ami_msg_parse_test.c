#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdio.h>

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
  const char pack1[] = "Action: CoreStatus\r\n\r\n";
  const char pack2[] = "Action: CoreStatus\r\n";
  const char pack3[] = "\r\n";
  const char pack4[] = "";
  const char pack5[] = "\r\n\r\n";
  const char pack6[] = "Stanza pack\r\n\r\n\r\n";

  assert_int_equal ( amiparse_stanza (pack1, sizeof(pack1)- 1),
                      RV_SUCCESS);
  assert_int_equal ( amiparse_stanza (pack2, sizeof(pack2)- 1),
                      RV_FAIL);
  assert_int_equal ( amiparse_stanza (pack3, sizeof(pack3)- 1),
                      RV_FAIL);
  assert_int_equal ( amiparse_stanza (pack4, sizeof(pack4)- 1),
                      RV_FAIL);
  assert_int_equal ( amiparse_stanza (pack5, sizeof(pack5)- 1),
                      RV_SUCCESS);
  assert_int_equal ( amiparse_stanza (pack6, sizeof(pack6)- 1),
                      RV_SUCCESS);

}

static void parse_packet_stanza_multiline (void **state)
{
  (void)*state;
  const char pack1[] = "Action: CoreStatus\r\nActionID: 1q2w3e4\r\n\r\n";
  const char pack2[] = "Action: CoreStatus\r\n\r\nActionID: 1q2w3e4\r\n";
  const char pack3[] =  "Action: Redirect\r\n"
                        "Channel: SIP/5558877449-C-00006cf\r\n"
                        "ExtraChannel: SIP/258-C-000069a\r\n"
                        "Context: outbound-local\r\n"
                        "ExtraContext: extens-internal\r\n"
                        "Priority: 1\r\n"
                        "ExtraPriority: 1\r\n\r\n";
  const char pack4[] =  "Action: Redirect\r\n"
                        "Channel: SIP/5558877449-C-00006cf\r\n"
                        "ExtraChannel: SIP/258-C-000069a\r\na\r\n";
  const char pack5[] = "Action: CoreStatus\r\n\r\nActionID: 1q2w3e4\r\n\r\n\r\n";
  const char pack6[] = "Action: CoreStatus\r\n\r\nActionID: 1q2w3e4\r\n\r\n\r\n\r\n";

  assert_int_equal(amiparse_stanza (pack1, sizeof(pack1) - 1), RV_SUCCESS);
  assert_int_equal(amiparse_stanza (pack2, sizeof(pack2) - 1), RV_FAIL);
  assert_int_equal(amiparse_stanza (pack3, sizeof(pack3) - 1), RV_SUCCESS);
  assert_int_equal(amiparse_stanza (pack4, sizeof(pack4) - 1), RV_FAIL);
  assert_int_equal(amiparse_stanza (pack5, sizeof(pack5) - 1), RV_SUCCESS);
  assert_int_equal(amiparse_stanza (pack6, sizeof(pack6) - 1), RV_SUCCESS);
}

static void parse_action_one_header (void **state)
{
  (void)*state;
  AMIPacket *pack;
  int ret;
  struct str *hv; // header value
  const char *str = "Action: CoreStatus\r\n\r\n";

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

  pack = amiparse_pack (str);
  assert_non_null (pack);
  assert_int_equal (pack->type, AMI_UNKNOWN);
  assert_int_equal (pack->size, 1);
  amipack_destroy (pack);
}

static void parse_invalid_pack (void **state)
{
  (void)*state;
  AMIPacket *pack;
  int ret;
  struct str *hv; // header value
  const char *str = "invalid pack that match stanza\r\n\r\n";

  pack = amiparse_pack (str);
  assert_null (pack);
}

static void parse_response_one_header_caseinsen (void **state)
{
  (void)*state;
  AMIPacket *pack;
  int ret;
  struct str *hv; // header value
  const char *str = "response: Fail\r\n\r\n";

  pack = amiparse_pack (str);
  assert_int_equal (pack->type, AMI_RESPONSE);
  assert_int_equal (pack->size, 1);
  hv = amiheader_value(pack, Response);
  assert_string_equal(hv->buf, "Fail");
  amipack_destroy (pack);
}

// TODO: multi headers
static void parse_multi_header (void **state)
{
  (void)*state;
  AMIPacket *pack;
  int ret;
  struct str *hv; // header value

  const char str_pack[] =  "Event: Hangup\r\n"
                           "Privilege: call,all\r\n"
                           "Channel: SIP/ipauthTp3BCHH7-00573401\r\n"
                           "Uniqueid: 1486254977.6071371\r\n"
                           "CallerIDNum: 18072280394\r\n"
                           "CallerIDName: <unknown>\r\n"
                           "ConnectedLineNum: 16478472089\r\n"
                           "ConnectedLineName: Detourlake\r\n"
                           "Cause: 16\r\n"
                           "Cause-txt: Normal Clearing\r\n\r\n";

  ret = amiparse_stanza (str_pack, sizeof(str_pack) - 1);
  assert_int_equal (RV_SUCCESS, ret);

  pack = amiparse_pack (str_pack);
  assert_int_equal (AMI_EVENT, pack->type);
  assert_int_equal (pack->size, 10);
  hv = amiheader_value(pack, Event);
  assert_string_equal(hv->buf, "Hangup");
  amipack_destroy (pack);
}

// TODO: headers with empty value
// TODO: multi string packet
// TODO: headers order. No ordering in AMI ver 2

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test (parse_prompt_header_11),
    cmocka_unit_test (parse_prompt_header_280),
    cmocka_unit_test (parse_not_prompt_pack),
    cmocka_unit_test (parse_packet_stanza),
    cmocka_unit_test (parse_packet_stanza_multiline),
    cmocka_unit_test (parse_action_one_header),
    cmocka_unit_test (parse_event_one_header),
    cmocka_unit_test (parse_response_one_header),
    cmocka_unit_test (parse_unknown_one_header),
    cmocka_unit_test (parse_invalid_pack),
    cmocka_unit_test (parse_response_one_header_caseinsen),
    cmocka_unit_test (parse_multi_header),
  };
  return cmocka_run_group_tests_name("Parse AMI package tests.", tests, NULL, NULL);
}
