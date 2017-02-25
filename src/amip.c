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
 * @file amip.c
 * @brief AMI (Asterisk Management Interface) messages read/create functions.
 *
 * @author Stas Kobzar <stas.kobzar@modulis.ca>
 */

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <stdio.h>

#include "amip.h"

#define valid_hdr_type(type) (type > 0 && type <= (sizeof(header_type_name)/sizeof(char*)))

static const char *pack_type_name[] = {
  "AMI_UNKNOWN", "AMI_PROMPT", "AMI_ACTION", "AMI_EVENT", "AMI_RESPONSE"
};

static const char *header_type_name[] = {
//{{{
  "UNKNOWN",               "CodecOrder",            "LastApplication",       "RemoteStationID",
  "ACL",                   "Codecs",                "LastCall",              "Resolution",
  "AMAflags",              "Command",               "LastData",              "Response",
  "Account",               "ConnectedLineName",     "Link",                  "Restart",
  "AccountCode",           "ConnectedLineNum",      "ListItems",             "SIPLastMsg",
  "Action",                "Context",               "LocalStationID",        "SIP-AuthInsecure",
  "Address",               "Count",                 "Location",              "SIP-FromDomain",
  "Address-IP",            "Data",                  "Loginchan",             "SIP-FromUser",
  "Address-Port",          "Default-Username",      "Logintime",             "SIP-NatSupport",
  "Agent",                 "Default-addr-IP",       "MD5SecretExist",        "Seconds",
  "AnswerTime",            "DestUniqueID",          "MOHSuggest",            "Secret",
  "Append",                "Destination",           "Mailbox",               "SecretExist",
  "Application",           "DestinationChannel",    "Membership",            "Shutdown",
  "Async",                 "DestinationContext",    "Message",               "Source",
  "AuthType",              "DialStatus",            "Mix",                   "SrcUniqueID",
  "BillableSeconds",       "Dialstring",            "NewMessages",           "StartTime",
  "Bridgestate",           "Direction",             "Newname",               "State",
  "Bridgetype",            "Disposition",           "ObjectName",            "Status",
  "CID-CallingPres",       "Domain",                "OldAccountCode",        "SubEvent",
  "CallerID",              "Duration",              "OldMessages",           "Time",
  "CallerID1",             "Dynamic",               "OldName",               "Timeout",
  "CallerID2",             "Endtime",               "Outgoinglimit",         "TransferRate",
  "CallerIDName",          "Event",                 "PagesTransferred",      "UniqueID",
  "CallerIDNum",           "EventList",             "Paused",                "Uniqueid",
  "Callgroup",             "Events",                "Peer",                  "Uniqueid1",
  "CallsTaken",            "Exten",                 "PeerStatus",            "Uniqueid2",
  "Cause",                 "Extension",             "Penalty",               "User",
  "Cause-txt",             "Family",                "Pickupgroup",           "UserField",
  "ChanObjectType",        "File",                  "Position",              "Username",
  "Channel",               "FileName",              "Priority",              "Val",
  "Channel1",              "Format",                "Privilege",             "Value",
  "Channel2",              "From",                  "Queue",                 "Variable",
  "ChannelState",          "Hint",                  "Reason",                "VoiceMailbox",
  "ChannelStateDesc",      "Incominglimit",         "RegExpire",             "Waiting",
  "ChannelType",           "Key",                   "RegExpiry",
  // added later
  "ActionID",              "ExtraChannel",          "ExtraContext",          "ExtraPriority",
  "Output",
}; //}}}

static const char *event_type_name[]  = {
//{{{
  "EVENT_UNKNOWN",        "ChannelTalkingStop",    "InvalidAccountID",      "PresenceStatus",
  "AGIExecEnd",            "ConfbridgeEnd",         "InvalidPassword",       "QueueCallerAbandon",
  "AGIExecStart",          "ConfbridgeJoin",        "InvalidTransport",      "QueueCallerJoin",
  "AOC-D",                 "ConfbridgeLeave",       "LoadAverageLimit",      "QueueCallerLeave",
  "AOC-E",                 "ConfbridgeMute",        "LocalBridge",           "QueueMemberAdded",
  "AOC-S",                 "ConfbridgeRecord",      "LocalOptimizationBeg",  "QueueMemberPause",
  "AgentCalled",           "ConfbridgeStart",       "LocalOptimizationEnd",  "QueueMemberPenalty",
  "AgentComplete",         "ConfbridgeStopRecord",  "MCID",                  "QueueMemberRemoved",
  "AgentConnect",          "ConfbridgeTalking",     "MWIGet",                "QueueMemberRinginuse",
  "AgentDump",             "ConfbridgeUnmute",      "MWIGetComplete",        "QueueMemberStatus",
  "AgentLogin",            "ContactStatus",         "MeetmeEnd",             "RTCPReceived",
  "AgentLogoff",           "ContactStatusDetail",   "MeetmeJoin",            "RTCPSent",
  "AgentRingNoAnswer",     "CoreShowChannel",       "MeetmeLeave",           "ReceiveFAX",
  "Agents",                "CoreShowChannelsComp",  "MeetmeMute",            "Registry",
  "AgentsComplete",        "DAHDIChannel",          "MeetmeTalkRequest",     "Reload",
  "Alarm",                 "DNDState",              "MeetmeTalking",         "RequestBadFormat",
  "AlarmClear",            "DeviceStateChange",     "MemoryLimit",           "RequestNotAllowed",
  "AorDetail",             "DialBegin",             "MiniVoiceMail",         "RequestNotSupported",
  "AsyncAGIEnd",           "DialEnd",               "MonitorStart",          "SIPQualifyPeerDone",
  "AsyncAGIExec",          "EndpointDetail",        "MonitorStop",           "SendFAX",
  "AsyncAGIStart",         "EndpointList",          "MusicOnHoldStart",      "SessionLimit",
  "AttendedTransfer",      "ExtensionStatus",       "MusicOnHoldStop",       "SessionTimeout",
  "AuthDetail",            "FAXSession",            "NewAccountCode",        "Shutdown",
  "AuthMethodNotAllowed",  "FAXSessionsComplete",   "NewCallerid",           "SoftHangupRequest",
  "BlindTransfer",         "FAXSessionsEntry",      "NewExten",              "SpanAlarm",
  "BridgeCreate",          "FAXStats",              "Newchannel",            "SpanAlarmClear",
  "BridgeDestroy",         "FAXStatus",             "Newstate",              "Status",
  "BridgeEnter",           "FailedACL",             "OriginateResponse",     "StatusComplete",
  "BridgeLeave",           "FullyBooted",           "ParkedCall",            "SuccessfulAuth",
  "CEL",                   "Hangup",                "ParkedCallGiveUp",      "TransportDetail",
  "Cdr",                   "HangupHandlerPop",      "ParkedCallSwap",        "UnParkedCall",
  "ChallengeResponseFai",  "HangupHandlerPush",     "ParkedCallTimeOut",     "UnexpectedAddress",
  "ChallengeSent",         "HangupHandlerRun",      "PeerStatus",            "Unhold",
  "ChanSpyStart",          "HangupRequest",         "Pickup",                "UserEvent",
  "ChanSpyStop",           "Hold",                  "PresenceStateChange",   "VarSet",
  "ChannelTalkingStart",   "IdentifyDetail",
}; //}}}

static const char *action_type_name[] = {
//{{{
  "ACTION_UNKNOWN",              "DBPut",                       "ParkedCalls",                 "SCCPShowDevice",
  "AGI",                         "DataGet",                     "Parkinglots",                 "SCCPShowDevices",
  "AOCMessage",                  "DeviceStateList",             "PauseMonitor",                "SCCPShowGlobals",
  "AbsoluteTimeout",             "DialplanExtensionAdd",        "Ping",                        "SCCPShowHintLineStates",
  "AgentLogoff",                 "DialplanExtensionRemove",     "PlayDTMF",                    "SCCPShowHintSubscriptions",
  "Agents",                      "Events",                      "PresenceState",               "SCCPShowLine",
  "Atxfer",                      "ExtensionState",              "PresenceStateList",           "SCCPShowLines",
  "BlindTransfer",               "ExtensionStateList",          "QueueAdd",                    "SCCPShowMWISubscriptions",
  "Bridge",                      "FAXSession",                  "QueueLog",                    "SCCPShowRefcount",
  "BridgeDestroy",               "FAXSessions",                 "QueueMemberRingInUse",        "SCCPShowSessions",
  "BridgeInfo",                  "FAXStats",                    "QueuePause",                  "SCCPShowSoftkeySets",
  "BridgeKick",                  "Filter",                      "QueuePenalty",                "SCCPStartCall",
  "BridgeList",                  "GetConfig",                   "QueueReload",                 "SCCPSystemMessage",
  "BridgeTechnologyList",        "GetConfigJSON",               "QueueRemove",                 "SCCPTokenAck",
  "BridgeTechnologySuspend",     "Getvar",                      "QueueReset",                  "SIPnotify",
  "BridgeTechnologyUnsuspend",   "Hangup",                      "QueueRule",                   "SIPpeers",
  "Challenge",                   "IAXnetstats",                 "QueueStatus",                 "SIPpeerstatus",
  "ChangeMonitor",               "IAXpeerlist",                 "QueueSummary",                "SIPqualifypeer",
  "Command",                     "IAXpeers",                    "Queues",                      "SIPshowpeer",
  "ConfbridgeKick",              "IAXregistry",                 "Redirect",                    "SIPshowregistry",
  "ConfbridgeList",              "ListCategories",              "Reload",                      "SendText",
  "ConfbridgeListRooms",         "ListCommands",                "SCCPAnswerCall",              "Setvar",
  "ConfbridgeLock",              "LocalOptimizeAway",           "SCCPAnswerCall1",             "ShowDialPlan",
  "ConfbridgeMute",              "LoggerRotate",                "SCCPConfigMetaData",          "SorceryMemoryCacheExpire",
  "ConfbridgeSetSingleVideoSrc", "Login",                       "SCCPDeviceAddLine",           "SorceryMemoryCacheExpireObject",
  "ConfbridgeStartRecord",       "Logoff",                      "SCCPDeviceRestart",           "SorceryMemoryCachePopulate",
  "ConfbridgeStopRecord",        "MailboxCount",                "SCCPDeviceSetDND",            "SorceryMemoryCacheStale",
  "ConfbridgeUnlock",            "MailboxStatus",               "SCCPDeviceUpdate",            "SorceryMemoryCacheStaleObject",
  "ConfbridgeUnmute",            "MessageSend",                 "SCCPDndDevice",               "Status",
  "ControlPlayback",             "MixMonitor",                  "SCCPHangupCall",              "StopMixMonitor",
  "CoreSettings",                "MixMonitorMute",              "SCCPHoldCall",                "StopMonitor",
  "CoreShowChannels",            "ModuleCheck",                 "SCCPLineForwardUpdate",       "UnpauseMonitor",
  "CoreStatus",                  "ModuleLoad",                  "SCCPListDevices",             "UpdateConfig",
  "CreateConfig",                "Monitor",                     "SCCPListLines",               "UserEvent",
  "DBDel",                       "MuteAudio",                   "SCCPMessageDevice",           "VoicemailRefresh",
  "DBDelTree",                   "Originate",                   "SCCPMessageDevices",          "VoicemailUsersList",
  "DBGet",                       "Park",                        "SCCPShowChannels",            "WaitEvent",
}; //}}}

struct str *str_set(const char *buf)
{
  struct str *res;
  int len = buf == NULL ? 0 : (int)strlen (buf);

  res = (struct str*) malloc (sizeof(struct str));
  assert (res != NULL);

  res->len = len;
  res->buf = (char *) malloc(len + 1); // +1 for \0
  assert(res->buf != NULL);

  for (int i = 0; i < len; i++) {
    res->buf[i] = buf[i];
  }

  res->buf[len] = '\0';

  return res;
}

void str_destroy (struct str *s)
{

  if (s->buf) {
    free(s->buf);
    s->buf = NULL;
  }

  if (s) {
    free(s);
    s = NULL;
  }

}

AMIHeader *amiheader_create ( enum header_type type,
                              const char *name,
                              const char *value)
{
  int len = 0;
  AMIHeader *header = (AMIHeader *) malloc (sizeof (AMIHeader));
  assert ( header != NULL );

  header->type = type;

  // add header name
  header->name = str_set (name);

  // add header value
  header->value = str_set (value);

  return header;
}

void amiheader_destroy (AMIHeader *hdr)
{
  if (hdr) {
    str_destroy (hdr->name);
    str_destroy (hdr->value);
    free(hdr);
  }
  hdr = NULL;
}

AMIPacket *amipack_init()
{
  AMIPacket *pack = (AMIPacket*) malloc(sizeof(AMIPacket));
  pack->size = 0;
  pack->length = 0;
  pack->type = AMI_UNKNOWN;
  pack->head = NULL;
  pack->tail = NULL;

  return pack;
}

void amipack_destroy (AMIPacket *pack)
{

  AMIHeader *hdr, *hnext;

  for ( hdr = pack->head; hdr != NULL; hdr = hnext) {

    hnext = hdr->next;
    amiheader_destroy (hdr);

  }

  if (pack != NULL) {

    free(pack);
    pack = NULL;

  }

}

int amipack_append( AMIPacket *pack,
                    enum header_type hdr_type,
                    const char *hdr_value)
{
  AMIHeader *header;

  if ( !valid_hdr_type(hdr_type) )
    return -1;

  header = amiheader_create (hdr_type,
                             (const char *)header_type_name[hdr_type],
                             hdr_value);

  return amipack_list_append (pack, header);
}

int amipack_append_unknown (AMIPacket *pack,
                            const char *name,
                            const char *value)
{
  AMIHeader *header = amiheader_create (HDR_UNKNOWN, name, value);

  return amipack_list_append (pack, header);
}

int amipack_list_append (AMIPacket *pack,
                         AMIHeader *header)
{
  pack->length += header->name->len + header->value->len + 4; // ": " = 2 char and CRLF = 2 char

  // first header becomes head and tail
  if (pack->size == 0) {
    pack->head = header;
  } else {
    pack->tail->next = header;
  }

  pack->tail = header;
  header->next  = NULL; // append function allways add header to tail of packet.

  pack->size++;

  return RV_SUCCESS;
}

int amiheader_to_str( AMIHeader *hdr,
                      char *buf)
{
  int len = 0;

  for (int i = 0; i < hdr->name->len; i++, len++) {
    buf[len] = hdr->name->buf[i];
  }
  buf[len++] = ':';
  buf[len++] = ' ';

  for (int i = 0; i < hdr->value->len; i++, len++) {
    buf[len] = hdr->value->buf[i];
  }
  buf[len++] = '\r';
  buf[len++] = '\n';

  return len;
}

struct str *amipack_to_str( AMIPacket *pack)
{

  int len = 0, size = 0;
  if (pack->size == 0) {
    return NULL;
  }
  char *str_pack = (char*) malloc (amipack_length (pack));
  struct str *res = (struct str*) malloc (sizeof(struct str));

  for (AMIHeader *hdr = pack->head; hdr; hdr = hdr->next) {
    len = amiheader_to_str (hdr, str_pack);
    str_pack += len;
    size += len;
  }

  *str_pack++ = '\r';  size++;
  *str_pack++ = '\n';  size++;
  *str_pack++ = '\0';  size++;
  // rewind str_pack
  str_pack = str_pack - size;

  res->len = size;
  res->buf = str_pack;
  return res;
}

struct str *amiheader_value(AMIPacket *pack, enum header_type type)
{
  struct str *hv = NULL;
  for (AMIHeader *hdr = pack->head; hdr; hdr = hdr->next) {
    if (hdr->type == type) {
      hv = hdr->value;
      break;
    }
  }
  return hv;
}

struct str *amiheader_value_by_hdr_name(AMIPacket *pack,
                                        const char *header_name)
{
  struct str *hv = NULL;
  for (AMIHeader *hdr = pack->head; hdr; hdr = hdr->next) {
    if (strcasecmp(hdr->name->buf, header_name ) == 0) {
      hv = hdr->value;
      break;
    }
  }
  return hv;
}

int amiparse_stanza (const char *packet, int size)
{
  if (size < 5) return RV_FAIL;

  // CRLF CRLF \000 - total 5 char
  if ( packet[size - 5] == '\r' &&
       packet[size - 4] == '\n' &&
       packet[size - 3] == '\r' &&
       packet[size - 2] == '\n'
      )
    return RV_SUCCESS;
  else
    return RV_FAIL;
}

char *substr (  const char* s,
                size_t len,
                size_t offset)
{
  int i, size;
  if (offset >= len) {
    return (char*)s;
  }
  size = len - offset + 1;

  char *res = (char*) malloc (size);
  assert(res != NULL);
  for (i = 0; offset < len; offset++, i++) {
    res[i] = s[offset];
  }
  res[len] = '\0';
  return res;
}

const char *header_name(enum header_type type)
{
  if(!valid_hdr_type(type)) return NULL;
  return header_type_name[type];
}
