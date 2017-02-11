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

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "amip.h"

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

void str_init(struct str *str, size_t size)
{
  if (size > 0) {

    str->len = size; // stanza CRLF 2 char
    str->buf = (char *) malloc(size);
    assert (str->buf != NULL);

  } else {

    str->len = 0;
    str->buf = NULL;

  }
}

void str_destroy (struct str *s)
{

  if (s->buf) {
    free(s->buf);
    s->buf = NULL;
  }

}

AMIHeader *amiheader_create ( enum header_type type,
                              const char *name,
                              const char *value)
{
  AMIHeader *header = (AMIHeader *) malloc (sizeof (AMIHeader));
  assert ( header != NULL );

  header->type = type;

  // add header name
  str_init (&header->name, strlen (name));
  memcpy(header->name.buf, name, header->name.len);

  // add header value
  str_init (&header->value, strlen (value));
  memcpy(header->value.buf, value, header->value.len);

  return header;
}

void amiheader_destroy (AMIHeader *hdr)
{
  if (hdr) {
    str_destroy (&hdr->name);
    str_destroy (&hdr->value);
    free(hdr);
  }
  hdr = NULL;
}

void amipack_init(AMIPacket *pack, enum pack_type type)
{
  pack->size = 0;
  pack->length = 0;
  pack->type = type;
  pack->head = NULL;
  pack->tail = NULL;

  return;
}

void amipack_destroy (AMIPacket *pack)
{

  AMIHeader *hdr, *hnext;

  for ( hdr = pack->head; hdr != NULL; hdr = hnext) {

    hnext = hdr->next;
    amiheader_destroy (hdr);

  }

  if (pack) {

    free(pack);
    pack = NULL;

  }

}

int amipack_append( AMIPacket *pack,
                    enum header_type hdr_type,
                    const char *hdr_value)
{
  AMIHeader *header = amiheader_create (hdr_type,
                                        (const char *)header_type_name[hdr_type],
                                        hdr_value);

  pack->length += header->name.len + header->value.len + 4; // ": " = 2 char and CRLF = 2 char

  // first header becomes head and tail
  if (pack->size == 0) {
    pack->head = header;
  } else {
    pack->tail->next = header;
  }

  pack->tail = header;
  header->next  = NULL; // append function allways add header to tail of packet.

  pack->size++;

  return 1;
}

int amiheader_to_str( AMIHeader *hdr,
                      struct str *s)
{
  int len = 0;

  strncat (s->buf, hdr->name.buf, hdr->name.len);
  strncat (s->buf, ": ", 2);
  strncat (s->buf, hdr->value.buf, hdr->value.len);
  strncat (s->buf, "\r\n", 2);

  len += hdr->name.len + hdr->value.len + 4;

  return len;
}

int amipack_to_str( AMIPacket *pack,
                    struct str *pstr)
{
  int len = 0;

  if (pack->size == 0) {
    str_init (pstr, 0);
    return 0;
  }

  str_init(pstr, pack->length + 2); // stanza CRLF 2 char

  for (AMIHeader *hdr = pack->head; hdr; hdr = hdr->next) {
    len += amiheader_to_str (hdr, pstr);
  }

  strncat (pstr->buf, "\r\n", 2);

  return len + 2;
}

