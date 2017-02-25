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

  assert_int_equal ( amiparse_stanza (pack1, sizeof(pack1)),
                      RV_SUCCESS);
  assert_int_equal ( amiparse_stanza (pack2, sizeof(pack2)),
                      RV_FAIL);
  assert_int_equal ( amiparse_stanza (pack3, sizeof(pack3)),
                      RV_FAIL);
  assert_int_equal ( amiparse_stanza (pack4, sizeof(pack4)),
                      RV_FAIL);
  assert_int_equal ( amiparse_stanza (pack5, sizeof(pack5)),
                      RV_SUCCESS);
  assert_int_equal ( amiparse_stanza (pack6, sizeof(pack6)),
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

  assert_int_equal(amiparse_stanza (pack1, sizeof(pack1)), RV_SUCCESS);
  assert_int_equal(amiparse_stanza (pack2, sizeof(pack2)), RV_FAIL);
  assert_int_equal(amiparse_stanza (pack3, sizeof(pack3)), RV_SUCCESS);
  assert_int_equal(amiparse_stanza (pack4, sizeof(pack4)), RV_FAIL);
  assert_int_equal(amiparse_stanza (pack5, sizeof(pack5)), RV_SUCCESS);
  assert_int_equal(amiparse_stanza (pack6, sizeof(pack6)), RV_SUCCESS);
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
                           "CallerIDNum: 18072280333\r\n"
                           "CallerIDName: <unknown>\r\n"
                           "ConnectedLineNum: 16478472022\r\n"
                           "ConnectedLineName: John Bar\r\n"
                           "Cause: 16\r\n"
                           "Cause-txt: Normal Clearing\r\n\r\n";

  ret = amiparse_stanza (str_pack, sizeof(str_pack));
  assert_int_equal (RV_SUCCESS, ret);

  pack = amiparse_pack (str_pack);
  assert_int_equal (AMI_EVENT, pack->type);
  assert_int_equal (pack->size, 10);

  hv = amiheader_value(pack, Event);
  assert_string_equal(hv->buf, "Hangup");

  hv = amiheader_value(pack, Privilege);
  assert_string_equal(hv->buf, "call,all");

  hv = amiheader_value(pack, Channel);
  assert_string_equal(hv->buf, "SIP/ipauthTp3BCHH7-00573401");

  hv = amiheader_value(pack, Uniqueid);
  assert_string_equal(hv->buf, "1486254977.6071371");

  hv = amiheader_value(pack, CallerIDNum);
  assert_string_equal(hv->buf, "18072280333");

  hv = amiheader_value(pack, CallerIDName);
  assert_string_equal(hv->buf, "<unknown>");

  hv = amiheader_value(pack, ConnectedLineNum);
  assert_string_equal(hv->buf, "16478472022");

  hv = amiheader_value(pack, ConnectedLineName);
  assert_string_equal(hv->buf, "John Bar");

  hv = amiheader_value(pack, Cause);
  assert_string_equal(hv->buf, "16");

  hv = amiheader_value(pack, Cause_txt);
  assert_string_equal(hv->buf, "Normal Clearing");

  amipack_destroy (pack);
}

static void parse_headers_with_empty_value (void **state)
{
  (void)*state;
  AMIPacket *pack;
  int ret;
  struct str *hv; // header value

  const char str_pack[] = "Event: Newchannel\r\n"
                          "Privilege: call,all\r\n"
                          "Channel: SIP/ipauthTp3BCHH7-00573539\r\n"
                          "ChannelState: 0\r\n"
                          "ChannelStateDesc: Down\r\n"
                          "CallerIDNum: \r\n"
                          "CallerIDName: \r\n"
                          "AccountCode: 81\r\n"
                          "Exten: \r\n"
                          "Context: mor\r\n"
                          "Uniqueid: 1486256739.6071687\r\n\r\n";

  ret = amiparse_stanza (str_pack, sizeof(str_pack));
  assert_int_equal (RV_SUCCESS, ret);

  pack = amiparse_pack (str_pack);
  assert_int_equal (AMI_EVENT, pack->type);

  assert_int_equal (pack->size, 11);
  assert_int_equal (amipack_length(pack), sizeof(str_pack));

  hv = amiheader_value(pack, Event);
  assert_string_equal(hv->buf, "Newchannel");

  hv = amiheader_value(pack, ChannelStateDesc);
  assert_string_equal(hv->buf, "Down");

  hv = amiheader_value(pack, CallerIDName);
  assert_string_equal(hv->buf, "");

  hv = amiheader_value(pack, Exten);
  assert_string_equal(hv->buf, "");

  hv = amiheader_value(pack, Uniqueid);
  assert_string_equal(hv->buf, "1486256739.6071687");

  amipack_destroy (pack);
}

static void parse_pack_with_empty_last_header (void **state)
{
  (void)*state;
  AMIPacket *pack;
  int ret;
  struct str *hv; // header value

  const char str_pack[] = "Event: Custom\r\n"
                          "Privilege: call,all\r\n"
                          "Exten: \r\n"
                          "Peer: \r\n\r\n";

  ret = amiparse_stanza (str_pack, sizeof(str_pack));
  assert_int_equal (RV_SUCCESS, ret);

  pack = amiparse_pack (str_pack);
  assert_int_equal (AMI_EVENT, pack->type);

  assert_int_equal (pack->size, 4);
  assert_int_equal (amipack_length(pack), sizeof(str_pack));

  hv = amiheader_value(pack, Event);
  assert_string_equal(hv->buf, "Custom");

  hv = amiheader_value(pack, Peer);
  assert_string_equal(hv->buf, "");

  amipack_destroy (pack);
}

static void parse_multi_str_compound (void **state)
{
  (void)*state;
  AMIPacket *pack;
  int ret;
  struct str *hv; // header value

  const char line1[] = "Response: Success\r\n";
  const char line2[] = "Message: Authentication accepted\r\n\r\n";
  int size = sizeof(line1) + sizeof(line2) + 1;
  char *str_pack = (char*) malloc (size);
  memset(str_pack, 0, size);

  strncat(str_pack, line1, strlen(line1) + 1);
  ret = amiparse_stanza (str_pack, strlen(str_pack));
  assert_int_equal (RV_FAIL, ret);

  strncat(str_pack, line2, strlen(line2) + 1);
  ret = amiparse_stanza (str_pack, strlen(str_pack) + 1);
  assert_int_equal (RV_SUCCESS, ret);

  pack = amiparse_pack (str_pack);
  assert_int_equal (AMI_RESPONSE, pack->type);

  hv = amiheader_value(pack, Message);
  assert_string_equal(hv->buf, "Authentication accepted");

  free(str_pack);
  amipack_destroy (pack);
}

static void parse_pack_unordered (void **state)
{
  (void)*state;
  AMIPacket *pack;
  int ret;
  struct str *hv; // header value

  const char str_pack[] = "Status: Fully Booted\r\n"
                          "Exten: \r\n"
                          "Event: FullyBooted\r\n"
                          "Privilege: system,all\r\n\r\n";

  ret = amiparse_stanza (str_pack, sizeof(str_pack));
  assert_int_equal (RV_SUCCESS, ret);

  pack = amiparse_pack (str_pack);
  assert_int_equal (AMI_EVENT, pack->type);

  hv = amiheader_value(pack, Event);
  assert_string_equal(hv->buf, "FullyBooted");

  amipack_destroy (pack);
}

static void parse_pack_with_invalid_header (void **state)
{
  (void)*state;
  AMIPacket *pack;
  int ret;
  struct str *hv; // header value

  const char str_pack[] = "Event: FullyBooted\r\n"
                          "invalid header\r\n"
                          "Exten: \r\n"
                          "Privilege: system,all\r\n\r\n";

  ret = amiparse_stanza (str_pack, sizeof(str_pack));
  assert_int_equal (RV_SUCCESS, ret);

  assert_null(amiparse_pack (str_pack));

}

static void parse_pack_command_output (void **state)
{
  (void)*state;
  AMIPacket *pack;
  int ret;
  struct str *hv; // header value

  const char str_pack[] = "Response: Follows\r\n"
                          "ActionID: 12345\r\n"
                          "Privilege: Command\r\n"
                          "Channel              Location             State   Application(Data)             \n"
                          "Local/5143607296@dia IVR_603@default:1    Up      AppDial((Outgoing Line))      \n"
                          "Local/5146020115@dia 5146020115@dial-foll Ring    Dial(SIP/5146020115@drspa.ntek\n"
                          "1754093 calls processed\n"
                          "--END COMMAND--\r\n\r\n";

  const char output_cmp[] = "Channel              Location             State   Application(Data)             \n"
                          "Local/5143607296@dia IVR_603@default:1    Up      AppDial((Outgoing Line))      \n"
                          "Local/5146020115@dia 5146020115@dial-foll Ring    Dial(SIP/5146020115@drspa.ntek\n"
                          "1754093 calls processed\n";

  ret = amiparse_stanza (str_pack, sizeof(str_pack));
  assert_int_equal (RV_SUCCESS, ret);

  pack = amiparse_pack (str_pack);
  assert_int_equal (AMI_RESPONSE, pack->type);

  hv = amiheader_value(pack, Privilege);
  assert_string_equal(hv->buf, "Command");

  hv = amiheader_value(pack, ActionID);
  assert_string_equal(hv->buf, "12345");

  hv = amiheader_value(pack, Output);
  assert_string_equal(hv->buf, output_cmp);

  amipack_destroy (pack);
}

/*
 * Command output compatibale with AMI v2
 * Command output is a value of the header "Output: "
 */
static void parse_pack_command_output_v2 (void **state)
{
  (void)*state;
  AMIPacket *pack;
  int ret;
  struct str *hv; // header value

  const char str_pack[] = "Response: Follows\r\n"
                          "Message: Command output follows\r\n"
                          "Output: Name/username             Host                                    Dyn Forcerport Comedia    ACL Port     Status      Description                      \r\n"
                          "8888/8888                 (Unspecified)                            D  Auto (No)  No             0        Unmonitored                                  \n"
                          "1 sip peers [Monitored: 0 online, 0 offline Unmonitored: 0 online, 1 offline]\n"
                          "--END COMMAND--\r\n\r\n";

  const char output_cmp[] = "Output: Name/username             Host                                    Dyn Forcerport Comedia    ACL Port     Status      Description                      \r\n"
                          "8888/8888                 (Unspecified)                            D  Auto (No)  No             0        Unmonitored                                  \n"
                          "1 sip peers [Monitored: 0 online, 0 offline Unmonitored: 0 online, 1 offline]\n";

  ret = amiparse_stanza (str_pack, sizeof(str_pack));
  assert_int_equal (RV_SUCCESS, ret);

  pack = amiparse_pack (str_pack);
  assert_int_equal (AMI_RESPONSE, pack->type);

  hv = amiheader_value(pack, Message);
  assert_string_equal(hv->buf, "Command output follows");

  hv = amiheader_value(pack, Output);
  assert_string_equal(hv->buf, output_cmp);

  amipack_destroy (pack);
}

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
    cmocka_unit_test (parse_headers_with_empty_value),
    cmocka_unit_test (parse_pack_with_empty_last_header),
    cmocka_unit_test (parse_multi_str_compound),
    cmocka_unit_test (parse_pack_unordered),
    cmocka_unit_test (parse_pack_with_invalid_header),
    cmocka_unit_test (parse_pack_command_output),
    cmocka_unit_test (parse_pack_command_output_v2),
  };
  return cmocka_run_group_tests_name("Parse AMI package tests.", tests, NULL, NULL);
}
