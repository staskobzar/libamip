/**
 * libamip -- Library with functions for read/create AMI packets
 * Copyright (C) 2016, Stas Kobzar <staskobzar@modulis.ca>
 *
 * This file is part of libamip.
 *
 * libamip is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * libamip is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libamip.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file parse_pack.c
 * @brief AMI (Asterisk Management Interface) packet parser.
 *
 * @author Stas Kobzar <stas.kobzar@modulis.ca>
 */

#include <stdio.h>
#include <string.h>
#include "amip.h"

/**
 * Commands to run when standard header parsed.
 * @param flag    Header type
 */
#define SET_HEADER(flag)  len = cur - tok; \
                          hdr_type = flag; \
                          goto yyc_key;

/**
 * Commands to run on Command AMI response header.
 * @param offset  Header name offset
 * @param flag    Header type
 */
#define CMD_HEADER(offset, flag) len = cur - tok - offset; tok += offset; \
                          while(*tok == ' ') { tok++; len--; } \
                          len -= 2; \
                          char *val = substr(tok, len, 0); \
                          amipack_append (pack, flag, val); \
                          if(val){free(val);}; tok = cur; goto yyc_command;

// introducing types:re2c for AMI packet
/*! re2c parcing conditions. */
enum yycond_pack {
  yyckey,
  yycvalue,
  yyccommand,
};

AMIPacket *amiparse_pack (const char *pack_str)
{
  AMIPacket *pack = amipack_init ();
  enum header_type hdr_type;
  const char *marker = pack_str;
  const char *cur    = marker;
  const char *ctxmarker;
  int c = yyckey;
  int len = 0;

  const char *tok = marker;
  char *hdr_name;

/*!re2c
  re2c:define:YYCTYPE  = "unsigned char";
  re2c:define:YYCURSOR = "cur";
  re2c:define:YYMARKER = "marker";
  re2c:define:YYCTXMARKER = "ctxmarker";
  re2c:define:YYCONDTYPE = "yycond_pack";
  re2c:define:YYGETCONDITION = "c";
  re2c:define:YYGETCONDITION:naked = 1;
  re2c:define:YYSETCONDITION = "c = @@;";
  re2c:define:YYSETCONDITION:naked = 1;
  re2c:yyfill:enable = 0;

  CRLF              = "\r\n";
  END_COMMAND       = "--END COMMAND--";

  ACTION            = 'Action';
  EVENT             = 'Event';
  RESPONSE          = 'Response';

  ACCOUNT           = 'Account';
  ACCOUNTCODE       = 'AccountCode';
  ACL               = 'ACL';
  ACTIONID          = 'ActionID';
  ADDRESS           = 'Address';
  ADDRESS_IP        = 'Address-IP';
  ADDRESS_PORT      = 'Address-Port';
  AGENT             = 'Agent';
  AMAFLAGS          = 'AMAflags';
  ANSWERTIME        = 'AnswerTime';
  APPEND            = 'Append';
  APPLICATION       = 'Application';
  ASYNC             = 'Async';
  AUTHTYPE          = 'AuthType';
  BILLABLESECONDS   = 'BillableSeconds';
  BRIDGESTATE       = 'Bridgestate';
  BRIDGETYPE        = 'Bridgetype';
  CALLERID          = 'CallerID';
  CALLERID1         = 'CallerID1';
  CALLERID2         = 'CallerID2';
  CALLERIDNAME      = 'CallerIDName';
  CALLERIDNUM       = 'CallerIDNum';
  CALLGROUP         = 'Callgroup';
  CALLSTAKEN        = 'CallsTaken';
  CAUSE             = 'Cause';
  CAUSE_TXT         = 'Cause-txt';
  CHANNEL           = 'Channel';
  CHANNEL1          = 'Channel1';
  CHANNEL2          = 'Channel2';
  CHANNELSTATE      = 'ChannelState';
  CHANNELSTATEDESC  = 'ChannelStateDesc';
  CHANNELTYPE       = 'ChannelType';
  CHANOBJECTTYPE    = 'ChanObjectType';
  CID_CALLINGPRES   = 'CID-CallingPres';
  CODECORDER        = 'CodecOrder';
  CODECS            = 'Codecs';
  COMMANDHDR        = 'Command';
  CONNECTEDLINENAME = 'ConnectedLineName';
  CONNECTEDLINENUM  = 'ConnectedLineNum';
  CONTEXT           = 'Context';
  COUNT             = 'Count';
  DATA              = 'Data';
  DEFAULT_ADDR_IP   = 'Default-addr-IP';
  DEFAULT_USERNAME  = 'Default-Username';
  DESTINATION       = 'Destination';
  DESTINATIONCHANNEL= 'DestinationChannel';
  DESTINATIONCONTEXT= 'DestinationContext';
  DESTUNIQUEID      = 'DestUniqueID';
  DIALSTATUS        = 'DialStatus';
  DIALSTRING        = 'Dialstring';
  DIRECTION         = 'Direction';
  DISPOSITION       = 'Disposition';
  DOMAIN            = 'Domain';
  DURATION          = 'Duration';
  DYNAMIC           = 'Dynamic';
  ENDTIME           = 'Endtime';
  EVENTLIST         = 'EventList';
  EVENTSHDR         = 'Events';
  EXTEN             = 'Exten';
  EXTENSION         = 'Extension';
  EXTRACHANNEL      = 'ExtraChannel';
  EXTRACONTEXT      = 'ExtraContext';
  EXTRAPRIORITY     = 'ExtraPriority';
  FAMILY            = 'Family';
  FILE              = 'File';
  FILENAME          = 'FileName';
  FORMAT            = 'Format';
  FROM              = 'From';
  HINT              = 'Hint';
  INCOMINGLIMIT     = 'Incominglimit';
  KEY               = 'Key';
  LASTAPPLICATION   = 'LastApplication';
  LASTCALL          = 'LastCall';
  LASTDATA          = 'LastData';
  LINK              = 'Link';
  LISTITEMS         = 'ListItems';
  LOCALSTATIONID    = 'LocalStationID';
  LOCATION          = 'Location';
  LOGINCHAN         = 'Loginchan';
  LOGINTIME         = 'Logintime';
  MAILBOX           = 'Mailbox';
  MD5SECRETEXIST    = 'MD5SecretExist';
  MEMBERSHIP        = 'Membership';
  MESSAGE           = 'Message';
  MIX               = 'Mix';
  MOHSUGGEST        = 'MOHSuggest';
  NEWMESSAGES       = 'NewMessages';
  NEWNAME           = 'Newname';
  OBJECTNAME        = 'ObjectName';
  OLDACCOUNTCODE    = 'OldAccountCode';
  OLDMESSAGES       = 'OldMessages';
  OLDNAME           = 'OldName';
  OUTGOINGLIMIT     = 'Outgoinglimit';
  OUTPUT            = 'Output';
  PAGESTRANSFERRED  = 'PagesTransferred';
  PAUSED            = 'Paused';
  PEER              = 'Peer';
  PEERSTATUSHDR     = 'PeerStatus';
  PENALTY           = 'Penalty';
  PICKUPGROUP       = 'Pickupgroup';
  POSITION          = 'Position';
  PRIORITY          = 'Priority';
  PRIVILEGE         = 'Privilege';
  QUEUE             = 'Queue';
  REASON            = 'Reason';
  REGEXPIRE         = 'RegExpire';
  REGEXPIRY         = 'RegExpiry';
  REMOTESTATIONID   = 'RemoteStationID';
  RESOLUTION        = 'Resolution';
  RESTART           = 'Restart';
  SECONDS           = 'Seconds';
  SECRET            = 'Secret';
  SECRETEXIST       = 'SecretExist';
  SHUTDOWNHDR       = 'Shutdown';
  SIP_AUTHINSECURE  = 'SIP-AuthInsecure';
  SIP_FROMDOMAIN    = 'SIP-FromDomain';
  SIP_FROMUSER      = 'SIP-FromUser';
  SIPLASTMSG        = 'SIPLastMsg';
  SIP_NATSUPPORT    = 'SIP-NatSupport';
  SOURCE            = 'Source';
  SRCUNIQUEID       = 'SrcUniqueID';
  STARTTIME         = 'StartTime';
  STATE             = 'State';
  STATUSHDR         = 'Status';
  SUBEVENT          = 'SubEvent';
  TIME              = 'Time';
  TIMEOUT           = 'Timeout';
  TRANSFERRATE      = 'TransferRate';
  UNIQUEID          = 'Uniqueid';
  UNIQUEID1         = 'Uniqueid1';
  UNIQUEID2         = 'Uniqueid2';
  USER              = 'User';
  USERFIELD         = 'UserField';
  USERNAME          = 'Username';
  VAL               = 'Val';
  VALUE             = 'Value';
  VARIABLE          = 'Variable';
  VOICEMAILBOX      = 'VoiceMailbox';
  WAITING           = 'Waiting';

  <*> *     {
              if (hdr_name) free (hdr_name);
              amipack_destroy (pack);
              return NULL;
            }
  <key,value> CRLF CRLF { goto done; }

  <key> ":" " "* { tok = cur; goto yyc_value; }
  <key> ":" " "* CRLF / [a-zA-Z] {
              tok = cur;
              if (hdr_type == HDR_UNKNOWN) {
                amipack_append_unknown (pack, hdr_name, NULL);
              } else {
                amipack_append (pack, hdr_type, NULL);
              }
              goto yyc_key;
            }
  <key> ":" " "* CRLF CRLF {
              tok = cur;
              if (hdr_type == HDR_UNKNOWN) {
                amipack_append_unknown (pack, hdr_name, NULL);
                if(hdr_name) free (hdr_name);
              } else {
                amipack_append (pack, hdr_type, NULL);
              }
              goto done;
            }
  <key> RESPONSE ":" " "* 'Follows' CRLF {
              len = cur - tok;
              tok = cur;
              amipack_type (pack, AMI_RESPONSE);
              amipack_append (pack, Response, "Follows");
              goto yyc_command;
            }
  <key> RESPONSE  {
              amipack_type (pack, AMI_RESPONSE);
              SET_HEADER(Response);
            }
  <key> ACTION {
              amipack_type (pack, AMI_ACTION);
              SET_HEADER(Action);
            }
  <key> EVENT  {
              amipack_type (pack, AMI_EVENT);
              SET_HEADER(Event);
            }

  <key> ACCOUNT           { SET_HEADER(Account); }
  <key> ACCOUNTCODE       { SET_HEADER(AccountCode); }
  <key> ACL               { SET_HEADER(ACL); }
  <key> ACTIONID          { SET_HEADER(ActionID); }
  <key> ADDRESS           { SET_HEADER(Address); }
  <key> ADDRESS_IP        { SET_HEADER(Address_IP); }
  <key> ADDRESS_PORT      { SET_HEADER(Address_Port); }
  <key> AGENT             { SET_HEADER(Agent); }
  <key> AMAFLAGS          { SET_HEADER(AMAflags); }
  <key> ANSWERTIME        { SET_HEADER(AnswerTime); }
  <key> APPEND            { SET_HEADER(Append); }
  <key> APPLICATION       { SET_HEADER(Application); }
  <key> ASYNC             { SET_HEADER(Async); }
  <key> AUTHTYPE          { SET_HEADER(AuthType); }
  <key> BILLABLESECONDS   { SET_HEADER(BillableSeconds); }
  <key> BRIDGESTATE       { SET_HEADER(Bridgestate); }
  <key> BRIDGETYPE        { SET_HEADER(Bridgetype); }
  <key> CALLERID          { SET_HEADER(CallerID); }
  <key> CALLERID1         { SET_HEADER(CallerID1); }
  <key> CALLERID2         { SET_HEADER(CallerID2); }
  <key> CALLERIDNAME      { SET_HEADER(CallerIDName); }
  <key> CALLERIDNUM       { SET_HEADER(CallerIDNum); }
  <key> CALLGROUP         { SET_HEADER(Callgroup); }
  <key> CALLSTAKEN        { SET_HEADER(CallsTaken); }
  <key> CAUSE             { SET_HEADER(Cause); }
  <key> CAUSE_TXT         { SET_HEADER(Cause_txt); }
  <key> CHANNEL           { SET_HEADER(Channel); }
  <key> CHANNEL1          { SET_HEADER(Channel1); }
  <key> CHANNEL2          { SET_HEADER(Channel2); }
  <key> CHANNELSTATE      { SET_HEADER(ChannelState); }
  <key> CHANNELSTATEDESC  { SET_HEADER(ChannelStateDesc); }
  <key> CHANNELTYPE       { SET_HEADER(ChannelType); }
  <key> CHANOBJECTTYPE    { SET_HEADER(ChanObjectType); }
  <key> CID_CALLINGPRES   { SET_HEADER(CID_CallingPres); }
  <key> CODECORDER        { SET_HEADER(CodecOrder); }
  <key> CODECS            { SET_HEADER(Codecs); }
  <key> COMMANDHDR        { SET_HEADER(CommandHdr); }
  <key> CONNECTEDLINENAME { SET_HEADER(ConnectedLineName); }
  <key> CONNECTEDLINENUM  { SET_HEADER(ConnectedLineNum); }
  <key> CONTEXT           { SET_HEADER(Context); }
  <key> COUNT             { SET_HEADER(Count); }
  <key> DATA              { SET_HEADER(Data); }
  <key> DEFAULT_ADDR_IP   { SET_HEADER(Default_addr_IP); }
  <key> DEFAULT_USERNAME  { SET_HEADER(Default_Username); }
  <key> DESTINATION       { SET_HEADER(Destination); }
  <key> DESTINATIONCHANNEL{ SET_HEADER(DestinationChannel); }
  <key> DESTINATIONCONTEXT{ SET_HEADER(DestinationContext); }
  <key> DESTUNIQUEID      { SET_HEADER(DestUniqueID); }
  <key> DIALSTATUS        { SET_HEADER(DialStatus); }
  <key> DIALSTRING        { SET_HEADER(Dialstring); }
  <key> DIRECTION         { SET_HEADER(Direction); }
  <key> DISPOSITION       { SET_HEADER(Disposition); }
  <key> DOMAIN            { SET_HEADER(Domain); }
  <key> DURATION          { SET_HEADER(Duration); }
  <key> DYNAMIC           { SET_HEADER(Dynamic); }
  <key> ENDTIME           { SET_HEADER(Endtime); }
  <key> EVENTLIST         { SET_HEADER(EventList); }
  <key> EVENTSHDR         { SET_HEADER(EventsHdr); }
  <key> EXTEN             { SET_HEADER(Exten); }
  <key> EXTENSION         { SET_HEADER(Extension); }
  <key> EXTRACHANNEL      { SET_HEADER(ExtraChannel); }
  <key> EXTRACONTEXT      { SET_HEADER(ExtraContext); }
  <key> EXTRAPRIORITY     { SET_HEADER(ExtraPriority); }
  <key> FAMILY            { SET_HEADER(Family); }
  <key> FILE              { SET_HEADER(File); }
  <key> FILENAME          { SET_HEADER(FileName); }
  <key> FORMAT            { SET_HEADER(Format); }
  <key> FROM              { SET_HEADER(From); }
  <key> HINT              { SET_HEADER(Hint); }
  <key> INCOMINGLIMIT     { SET_HEADER(Incominglimit); }
  <key> KEY               { SET_HEADER(Key); }
  <key> LASTAPPLICATION   { SET_HEADER(LastApplication); }
  <key> LASTCALL          { SET_HEADER(LastCall); }
  <key> LASTDATA          { SET_HEADER(LastData); }
  <key> LINK              { SET_HEADER(Link); }
  <key> LISTITEMS         { SET_HEADER(ListItems); }
  <key> LOCALSTATIONID    { SET_HEADER(LocalStationID); }
  <key> LOCATION          { SET_HEADER(Location); }
  <key> LOGINCHAN         { SET_HEADER(Loginchan); }
  <key> LOGINTIME         { SET_HEADER(Logintime); }
  <key> MAILBOX           { SET_HEADER(Mailbox); }
  <key> MD5SECRETEXIST    { SET_HEADER(MD5SecretExist); }
  <key> MEMBERSHIP        { SET_HEADER(Membership); }
  <key> MESSAGE           { SET_HEADER(Message); }
  <key> MIX               { SET_HEADER(Mix); }
  <key> MOHSUGGEST        { SET_HEADER(MOHSuggest); }
  <key> NEWMESSAGES       { SET_HEADER(NewMessages); }
  <key> NEWNAME           { SET_HEADER(Newname); }
  <key> OBJECTNAME        { SET_HEADER(ObjectName); }
  <key> OLDACCOUNTCODE    { SET_HEADER(OldAccountCode); }
  <key> OLDMESSAGES       { SET_HEADER(OldMessages); }
  <key> OLDNAME           { SET_HEADER(OldName); }
  <key> OUTGOINGLIMIT     { SET_HEADER(Outgoinglimit); }
  <key> OUTPUT            { SET_HEADER(Output); }
  <key> PAGESTRANSFERRED  { SET_HEADER(PagesTransferred); }
  <key> PAUSED            { SET_HEADER(Paused); }
  <key> PEER              { SET_HEADER(Peer); }
  <key> PEERSTATUSHDR     { SET_HEADER(PeerStatusHdr); }
  <key> PENALTY           { SET_HEADER(Penalty); }
  <key> PICKUPGROUP       { SET_HEADER(Pickupgroup); }
  <key> POSITION          { SET_HEADER(Position); }
  <key> PRIORITY          { SET_HEADER(Priority); }
  <key> PRIVILEGE         { SET_HEADER(Privilege); }
  <key> QUEUE             { SET_HEADER(Queue); }
  <key> REASON            { SET_HEADER(Reason); }
  <key> REGEXPIRE         { SET_HEADER(RegExpire); }
  <key> REGEXPIRY         { SET_HEADER(RegExpiry); }
  <key> REMOTESTATIONID   { SET_HEADER(RemoteStationID); }
  <key> RESOLUTION        { SET_HEADER(Resolution); }
  <key> RESTART           { SET_HEADER(Restart); }
  <key> SECONDS           { SET_HEADER(Seconds); }
  <key> SECRET            { SET_HEADER(Secret); }
  <key> SECRETEXIST       { SET_HEADER(SecretExist); }
  <key> SHUTDOWNHDR       { SET_HEADER(ShutdownHdr); }
  <key> SIP_AUTHINSECURE  { SET_HEADER(SIP_AuthInsecure); }
  <key> SIP_FROMDOMAIN    { SET_HEADER(SIP_FromDomain); }
  <key> SIP_FROMUSER      { SET_HEADER(SIP_FromUser); }
  <key> SIPLASTMSG        { SET_HEADER(SIPLastMsg); }
  <key> SIP_NATSUPPORT    { SET_HEADER(SIP_NatSupport); }
  <key> SOURCE            { SET_HEADER(Source); }
  <key> SRCUNIQUEID       { SET_HEADER(SrcUniqueID); }
  <key> STARTTIME         { SET_HEADER(StartTime); }
  <key> STATE             { SET_HEADER(State); }
  <key> STATUSHDR         { SET_HEADER(StatusHdr); }
  <key> SUBEVENT          { SET_HEADER(SubEvent); }
  <key> TIME              { SET_HEADER(Time); }
  <key> TIMEOUT           { SET_HEADER(Timeout); }
  <key> TRANSFERRATE      { SET_HEADER(TransferRate); }
  <key> UNIQUEID          { SET_HEADER(Uniqueid); }
  <key> UNIQUEID1         { SET_HEADER(Uniqueid1); }
  <key> UNIQUEID2         { SET_HEADER(Uniqueid2); }
  <key> USER              { SET_HEADER(User); }
  <key> USERFIELD         { SET_HEADER(UserField); }
  <key> USERNAME          { SET_HEADER(Username); }
  <key> VAL               { SET_HEADER(Val); }
  <key> VALUE             { SET_HEADER(Value); }
  <key> VARIABLE          { SET_HEADER(Variable); }
  <key> VOICEMAILBOX      { SET_HEADER(VoiceMailbox); }
  <key> WAITING           { SET_HEADER(Waiting); }
  <key> [^: ]+ {
              len = cur - tok - 1;
              tok++;
              hdr_type = HDR_UNKNOWN;
              hdr_name = substr (tok, len, 0);
              goto yyc_key;
            }

  <value> CRLF / [a-zA-Z] { tok = cur - 1; goto yyc_key; }
  <value> [^\r\n]* {
              len = cur - tok;
              char *val = substr(tok, len, 0);
              if (hdr_type == HDR_UNKNOWN) {
                amipack_append_unknown (pack, hdr_name, val);
                if(hdr_name) free (hdr_name);
              } else {
                amipack_append (pack, hdr_type, val);
              }
              if(val) free (val);
              goto yyc_value;
            }

  <command> PRIVILEGE ":" .* CRLF { CMD_HEADER(10, Privilege); }
  <command> ACTIONID ":" .* CRLF  { CMD_HEADER(9, ActionID); }
  <command> MESSAGE ":" .* CRLF   { CMD_HEADER(8, Message); }
  <command> OUTPUT ":" " "?       { tok = cur; goto yyc_command; }
  <command> .* "\r"? "\n"         { goto yyc_command; }
  <command> END_COMMAND CRLF CRLF {
              len = cur - tok - 19; // output minus command end tag
              char *val = substr(tok, len, 0);
              amipack_append (pack, Output, val);
              if(val) free (val);
              goto done;
            }
*/

done:
  return pack;
}
