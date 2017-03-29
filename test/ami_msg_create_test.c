#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdio.h>
#include "amip.h"

static int setup_pack(void **state)
{
  *state = (AMIPacket *) amipack_init ();
  return 0;
}

static int teardown_pack(void **state)
{
  amipack_destroy (*state);
  return 0;
}

static void create_pack_with_no_header (void **state)
{
  struct str *pack_str;
  AMIPacket *pack = *state;

  assert_int_equal (pack->size, 0);
  assert_null ( amipack_to_str(pack) );
}

static void create_pack_with_single_header (void **state)
{
  struct str *pack_str;
  AMIPacket *pack = *state;

  amipack_type(pack, AMI_ACTION);
  amipack_append (pack, Action, "CoreStatus");

  assert_int_equal (pack->size, 1);

  pack_str = amipack_to_str (pack);
  assert_memory_equal (pack_str->buf, "Action: CoreStatus\r\n\r\n", pack_str->len);

  assert_int_equal(pack_str->len, amipack_length(pack));

  str_destroy (pack_str);
}

static void create_pack_with_two_headers (void **state)
{
  struct str *pack_str;
  AMIPacket *pack = *state;

  amipack_type(pack, AMI_ACTION);
  amipack_append (pack, Action, "Command");
  amipack_append (pack, CommandHdr, "core show uptime");

  assert_int_equal (pack->size, 2);

  pack_str = amipack_to_str (pack);
  assert_memory_equal (pack_str->buf,
      "Action: Command\r\nCommand: core show uptime\r\n\r\n",
      pack_str->len);

  assert_int_equal(pack_str->len, amipack_length (pack));
  str_destroy (pack_str);
}

static void create_pack_with_three_headers (void **state)
{
  struct str *pack_str;
  AMIPacket *pack = *state;

  amipack_type(pack, AMI_ACTION);
  amipack_append (pack, Action, "ExtensionState");
  amipack_append (pack, Exten, "5555");
  amipack_append (pack, Context, "inbound-local");

  assert_int_equal (pack->size, 3);

  pack_str = amipack_to_str (pack);
  assert_memory_equal (pack_str->buf,
      "Action: ExtensionState\r\nExten: 5555\r\nContext: inbound-local\r\n\r\n",
      pack_str->len);

  assert_int_equal(pack_str->len, amipack_length (pack));
  str_destroy (pack_str);
}

static void create_pack_with_multi_headers (void **state)
{
  const char *pack_result = "Action: Redirect\r\n"
                            "Channel: SIP/5558877449-C-00006cf\r\n"
                            "ExtraChannel: SIP/258-C-000069a\r\n"
                            "Context: outbound-local\r\n"
                            "ExtraContext: extens-internal\r\n"
                            "Priority: 1\r\n"
                            "ExtraPriority: 1\r\n\r\n";
  struct str *pack_str;
  AMIPacket *pack = *state;

  amipack_type(pack, AMI_ACTION);
  amipack_append (pack, Action, "Redirect");
  amipack_append (pack, Channel, "SIP/5558877449-C-00006cf");
  amipack_append (pack, ExtraChannel, "SIP/258-C-000069a");
  amipack_append (pack, Context, "outbound-local");
  amipack_append (pack, ExtraContext, "extens-internal");
  amipack_append (pack, Priority, "1");
  amipack_append (pack, ExtraPriority, "1");

  assert_int_equal (pack->size, 7);

  pack_str = amipack_to_str (pack);

  assert_memory_equal (pack_str->buf, pack_result, pack_str->len);

  assert_int_equal(pack_str->len, amipack_length (pack));
  str_destroy (pack_str);
}

static void create_pack_with_none_existing_header (void **state)
{
  struct str *pack_str;
  AMIPacket *pack = *state;
  int rv = 0;

  amipack_type(pack, AMI_ACTION);

  rv = amipack_append (pack, 1024*1024, "InvalidHeader");
  assert_int_equal(rv, -1);

  rv = amipack_append (pack, 0, "InvalidHeader");
  assert_int_equal(rv, -1);

  rv = amipack_append (pack, -4, "InvalidHeader");
  assert_int_equal(rv, -1);

  rv = amipack_append (pack, Action, "CoreStatus");
  assert_int_equal(rv, 0);

  assert_int_equal (pack->size, 1);
  pack_str = amipack_to_str (pack);
  assert_memory_equal (pack_str->buf, "Action: CoreStatus\r\n\r\n", pack_str->len);
  assert_int_equal(pack_str->len, amipack_length (pack));
  str_destroy (pack_str);
}

static void create_pack_with_unknown_header (void **state)
{
  struct str *pack_str;
  AMIPacket *pack = *state;
  int rv = 0;

  amipack_type(pack, AMI_ACTION);

  amipack_append (pack, Action, "ShowDate");
  amipack_append_unknown (pack, "Calendar", "Julian");
  amipack_append_unknown (pack, "Format", "YYYY-MM-DD");

  assert_int_equal (pack->size, 3);
  pack_str = amipack_to_str (pack);
  assert_memory_equal (pack_str->buf,
      "Action: ShowDate\r\nCalendar: Julian\r\nFormat: YYYY-MM-DD\r\n\r\n",
      pack_str->len);
  assert_int_equal(pack_str->len, amipack_length (pack));
  str_destroy (pack_str);
}

static void create_pack_with_empty_header (void **state)
{
  struct str *pack_str;
  AMIPacket *pack = *state;
  int rv = 0;

  amipack_type(pack, AMI_EVENT);

  amipack_append (pack, Event, "Newchannel");
  amipack_append (pack, ChannelState, "0");
  amipack_append (pack, CallerIDNum, "");
  amipack_append (pack, CallerIDName, NULL);
  amipack_append_unknown (pack, "Exten1", "");
  amipack_append (pack, Context, "mor");

  assert_int_equal (pack->size, 6);
  pack_str = amipack_to_str (pack);
  assert_memory_equal (pack_str->buf,
      "Event: Newchannel\r\nChannelState: 0\r\nCallerIDNum: \r\nCallerIDName: \r\nExten1: \r\nContext: mor\r\n\r\n",
      pack_str->len);
  assert_int_equal(pack_str->len, amipack_length (pack));
  str_destroy (pack_str);
}

static void create_pack_with_empty_last_header (void **state)
{
  struct str *pack_str;
  AMIPacket *pack = *state;
  int rv = 0;

  amipack_type(pack, AMI_EVENT);

  amipack_append (pack, Event, "Newchannel");
  amipack_append (pack, ChannelState, "0");
  amipack_append (pack, CallerIDNum, "");

  assert_int_equal (pack->size, 3);
  pack_str = amipack_to_str (pack);
  assert_memory_equal (pack_str->buf,
      "Event: Newchannel\r\nChannelState: 0\r\nCallerIDNum: \r\n\r\n",
      pack_str->len);
  assert_int_equal(pack_str->len, amipack_length (pack));
  str_destroy (pack_str);
}

static void pack_find_headers (void **state)
{
  AMIPacket *pack = *state;
  struct str *hv; // header value

  amipack_type(pack, AMI_EVENT);
  amipack_append (pack, Event,      "Hangup");
  amipack_append (pack, Privilege,  "dialplan,all");
  amipack_append (pack, Channel,    "PJSIP/kermit-00000001");
  amipack_append (pack, Uniqueid,   "asterisk-1368479157.1");
  amipack_append (pack, ChannelState, "6");
  amipack_append (pack, ChannelStateDesc, "Up");
  amipack_append (pack, Cause,      "16");
  amipack_append (pack, Cause_txt,  "Normal Clearing");

  // found header value
  hv = amiheader_value(pack, Cause);
  assert_memory_equal(hv->buf, "16", hv->len);

  hv = amiheader_value(pack, Uniqueid);
  assert_memory_equal(hv->buf, "asterisk-1368479157.1", hv->len);

  // header value not found
  assert_null ( amiheader_value (pack, RemoteStationID) );

  assert_int_equal (pack->size, 8);
  assert_int_equal (pack->type, AMI_EVENT);

}

static void pack_find_header_by_name (void **state)
{
  AMIPacket *pack = *state;
  struct str *hv; // header value

  amipack_type(pack, AMI_EVENT);
  amipack_append (pack, Event,      "Hangup");
  amipack_append (pack, Privilege,  "dialplan,all");
  amipack_append (pack, Channel,    "PJSIP/kermit-00000001");
  amipack_append_unknown (pack, "SIPDomain", "example.com");
  amipack_append_unknown (pack, "Billsec", "352");

  assert_int_equal (pack->size, 5);
  // found header value
  hv = amiheader_value_by_hdr_name(pack, "Channel");
  assert_memory_equal(hv->buf, "PJSIP/kermit-00000001", hv->len);

  hv = amiheader_value_by_hdr_name(pack, "sipdomain");
  assert_memory_equal(hv->buf, "example.com", hv->len);

  hv = amiheader_value_by_hdr_name(pack, "Billsec");
  assert_memory_equal(hv->buf, "352", hv->len);

}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup_teardown (create_pack_with_no_header, setup_pack, teardown_pack),
    cmocka_unit_test_setup_teardown (create_pack_with_single_header, setup_pack, teardown_pack),
    cmocka_unit_test_setup_teardown (create_pack_with_two_headers, setup_pack, teardown_pack),
    cmocka_unit_test_setup_teardown (create_pack_with_three_headers, setup_pack, teardown_pack),
    cmocka_unit_test_setup_teardown (create_pack_with_multi_headers, setup_pack, teardown_pack),
    cmocka_unit_test_setup_teardown (create_pack_with_none_existing_header, setup_pack, teardown_pack),
    cmocka_unit_test_setup_teardown (create_pack_with_unknown_header, setup_pack, teardown_pack),
    cmocka_unit_test_setup_teardown (create_pack_with_empty_header, setup_pack, teardown_pack),
    cmocka_unit_test_setup_teardown (create_pack_with_empty_last_header, setup_pack, teardown_pack),
    cmocka_unit_test_setup_teardown (pack_find_headers, setup_pack, teardown_pack),
    cmocka_unit_test_setup_teardown (pack_find_header_by_name, setup_pack, teardown_pack),
  };

  //cmocka_set_message_output(CM_OUTPUT_TAP);

  return cmocka_run_group_tests_name("Create AMI package tests.", tests, NULL, NULL);
}
