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
 * @file amip.h
 * @brief AMI (Asterisk Management Interface) messages
 * read/create functions interface.
 * AMI packet is implemented as linked list of headers.
 *
 * @author Stas Kobzar <stas.kobzar@modulis.ca>
 */

#ifndef __AMIP_H
#define __AMIP_H

#include <stdlib.h>
#include <string.h>

/*! Value to return on success. */
#define RV_SUCCESS 0
/*! Value to return on fail. */
#define RV_FAIL    !RV_SUCCESS

/*!
 * Return length of the packet as string representation.
 * All headers length + CRLF stanza (2 bytes)
 */
#define amipack_length(pack) (pack)->length + 2

/*! Set AMI packet type. */
#define amipack_type(pack, ptype) (pack)->type = ptype

/*! Number of headers in packet. */
#define amipack_size(pack) (pack)->size

/*!
 * String structure for libamip library.
 * Stores char array and its length.
 */
struct str {
  char    *buf; /*!< String buffer. */
  size_t  len;  /*!< String length. */
};

/*! AMI packet types. */
enum pack_type {
  AMI_UNKNOWN, AMI_PROMPT, AMI_ACTION, AMI_EVENT, AMI_RESPONSE
};

/*! AMI headers types. Extracted from Asterisk source. */
enum header_type {
//{{{
  HDR_UNKNOWN,             CodecOrder,              LastApplication,         RemoteStationID,
  ACL,                     Codecs,                  LastCall,                Resolution,
  AMAflags,                CommandHdr,              LastData,                Response,
  Account,                 ConnectedLineName,       Link,                    Restart,
  AccountCode,             ConnectedLineNum,        ListItems,               SIPLastMsg,
  Action,                  Context,                 LocalStationID,          SIP_AuthInsecure,
  Address,                 Count,                   Location,                SIP_FromDomain,
  Address_IP,              Data,                    Loginchan,               SIP_FromUser,
  Address_Port,            Default_Username,        Logintime,               SIP_NatSupport,
  Agent,                   Default_addr_IP,         MD5SecretExist,          Seconds,
  AnswerTime,              DestUniqueID,            MOHSuggest,              Secret,
  Append,                  Destination,             Mailbox,                 SecretExist,
  Application,             DestinationChannel,      Membership,              ShutdownHdr,
  Async,                   DestinationContext,      Message,                 Source,
  AuthType,                DialStatus,              Mix,                     SrcUniqueID,
  BillableSeconds,         Dialstring,              NewMessages,             StartTime,
  Bridgestate,             Direction,               Newname,                 State,
  Bridgetype,              Disposition,             ObjectName,              StatusHdr,
  CID_CallingPres,         Domain,                  OldAccountCode,          SubEvent,
  CallerID,                Duration,                OldMessages,             Time,
  CallerID1,               Dynamic,                 OldName,                 Timeout,
  CallerID2,               Endtime,                 Outgoinglimit,           TransferRate,
  CallerIDName,            Event,                   PagesTransferred,        UniqueID,
  CallerIDNum,             EventList,               Paused,                  Uniqueid,
  Callgroup,               EventsHdr,               Peer,                    Uniqueid1,
  CallsTaken,              Exten,                   PeerStatusHdr,           Uniqueid2,
  Cause,                   Extension,               Penalty,                 User,
  Cause_txt,               Family,                  Pickupgroup,             UserField,
  ChanObjectType,          File,                    Position,                Username,
  Channel,                 FileName,                Priority,                Val,
  Channel1,                Format,                  Privilege,               Value,
  Channel2,                From,                    Queue,                   Variable,
  ChannelState,            Hint,                    Reason,                  VoiceMailbox,
  ChannelStateDesc,        Incominglimit,           RegExpire,               Waiting,
  ChannelType,             Key,                     RegExpiry,
  // added later
  ActionID,                ExtraChannel,            ExtraContext,            ExtraPriority,
  Output,
}; //}}}

/*! AMI Event header types. Extracted from Asterisk source. */
enum event_type {
//{{{
  EVENT_UNKNOWN,           ChannelTalkingStop,      InvalidAccountID,        PresenceStatus,
  AGIExecEnd,              ConfbridgeEnd,           InvalidPassword,         QueueCallerAbandon,
  AGIExecStart,            ConfbridgeJoin,          InvalidTransport,        QueueCallerJoin,
  AOC_D,                   ConfbridgeLeave,         LoadAverageLimit,        QueueCallerLeave,
  AOC_E,                   ConfbridgeMuteEvent,     LocalBridge,             QueueMemberAdded,
  AOC_S,                   ConfbridgeRecord,        LocalOptimizationBeg,    QueueMemberPause,
  AgentCalled,             ConfbridgeStart,         LocalOptimizationEnd,    QueueMemberPenalty,
  AgentComplete,           ConfbridgeStopRecordEvent, MCID,                  QueueMemberRemoved,
  AgentConnect,            ConfbridgeTalking,       MWIGet,                  QueueMemberRinginuse,
  AgentDump,               ConfbridgeUnmuteEvent,   MWIGetComplete,          QueueMemberStatus,
  AgentLogin,              ContactStatus,           MeetmeEnd,               RTCPReceived,
  AgentLogoffEvent,        ContactStatusDetail,     MeetmeJoin,              RTCPSent,
  AgentRingNoAnswer,       CoreShowChannel,         MeetmeLeave,             ReceiveFAX,
  AgentsEvent,             CoreShowChannelsComp,    MeetmeMute,              Registry,
  AgentsComplete,          DAHDIChannel,            MeetmeTalkRequest,       ReloadEvent,
  Alarm,                   DNDState,                MeetmeTalking,           RequestBadFormat,
  AlarmClear,              DeviceStateChange,       MemoryLimit,             RequestNotAllowed,
  AorDetail,               DialBegin,               MiniVoiceMail,           RequestNotSupported,
  AsyncAGIEnd,             DialEnd,                 MonitorStart,            SIPQualifyPeerDone,
  AsyncAGIExec,            EndpointDetail,          MonitorStop,             SendFAX,
  AsyncAGIStart,           EndpointList,            MusicOnHoldStart,        SessionLimit,
  AttendedTransfer,        ExtensionStatus,         MusicOnHoldStop,         SessionTimeout,
  AuthDetail,              FAXSessionEvent,         NewAccountCode,          ShutdownEvent,
  AuthMethodNotAllowed,    FAXSessionsComplete,     NewCallerid,             SoftHangupRequest,
  BlindTransferEvent,      FAXSessionsEntry,        NewExten,                SpanAlarm,
  BridgeCreate,            FAXStatsEvent,           Newchannel,              SpanAlarmClear,
  BridgeDestroyEvent,      FAXStatus,               Newstate,                StatusEvent,
  BridgeEnter,             FailedACL,               OriginateResponse,       StatusComplete,
  BridgeLeave,             FullyBooted,             ParkedCall,              SuccessfulAuth,
  CEL,                     HangupEvent,             ParkedCallGiveUp,        TransportDetail,
  Cdr,                     HangupHandlerPop,        ParkedCallSwap,          UnParkedCall,
  ChallengeResponseFai,    HangupHandlerPush,       ParkedCallTimeOut,       UnexpectedAddress,
  ChallengeSent,           HangupHandlerRun,        PeerStatusEvent,         Unhold,
  ChanSpyStart,            HangupRequest,           Pickup,                  UserEventEvent,
  ChanSpyStop,             Hold,                    PresenceStateChange,     VarSet,
  ChannelTalkingStart,     IdentifyDetail,
}; //}}}

/*! AMI Action header types. Extracted from Asterisk source. */
enum action_type {
//{{{
  ACTION_UNKNOWN,               DBPut,                        ParkedCalls,                  SCCPShowDevice,
  AGI,                          DataGet,                      Parkinglots,                  SCCPShowDevices,
  AOCMessage,                   DeviceStateList,              PauseMonitor,                 SCCPShowGlobals,
  AbsoluteTimeout,              DialplanExtensionAdd,         Ping,                         SCCPShowHintLineStates,
  AgentLogoffAction,            DialplanExtensionRemove,      PlayDTMF,                     SCCPShowHintSubscriptions,
  AgentsAction,                 EventsAction,                 PresenceState,                SCCPShowLine,
  Atxfer,                       ExtensionState,               PresenceStateList,            SCCPShowLines,
  BlindTransferAction,          ExtensionStateList,           QueueAdd,                     SCCPShowMWISubscriptions,
  Bridge,                       FAXSessionAction,             QueueLog,                     SCCPShowRefcount,
  BridgeDestroyAction,          FAXSessions,                  QueueMemberRingInUse,         SCCPShowSessions,
  BridgeInfo,                   FAXStatsAction,               QueuePause,                   SCCPShowSoftkeySets,
  BridgeKick,                   Filter,                       QueuePenalty,                 SCCPStartCall,
  BridgeList,                   GetConfig,                    QueueReload,                  SCCPSystemMessage,
  BridgeTechnologyList,         GetConfigJSON,                QueueRemove,                  SCCPTokenAck,
  BridgeTechnologySuspend,      Getvar,                       QueueReset,                   SIPnotify,
  BridgeTechnologyUnsuspend,    HangupAction,                 QueueRule,                    SIPpeers,
  Challenge,                    IAXnetstats,                  QueueStatus,                  SIPpeerstatus,
  ChangeMonitor,                IAXpeerlist,                  QueueSummary,                 SIPqualifypeer,
  CommandAction,                IAXpeers,                     Queues,                       SIPshowpeer,
  ConfbridgeKick,               IAXregistry,                  Redirect,                     SIPshowregistry,
  ConfbridgeList,               ListCategories,               ReloadAction,                 SendText,
  ConfbridgeListRooms,          ListCommands,                 SCCPAnswerCall,               Setvar,
  ConfbridgeLock,               LocalOptimizeAway,            SCCPAnswerCall1,              ShowDialPlan,
  ConfbridgeMuteAction,         LoggerRotate,                 SCCPConfigMetaData,           SorceryMemoryCacheExpire,
  ConfbridgeSetSingleVideoSrc,  Login,                        SCCPDeviceAddLine,            SorceryMemoryCacheExpireObject,
  ConfbridgeStartRecordAction,  Logoff,                       SCCPDeviceRestart,            SorceryMemoryCachePopulate,
  ConfbridgeStopRecord,         MailboxCount,                 SCCPDeviceSetDND,             SorceryMemoryCacheStale,
  ConfbridgeUnlock,             MailboxStatus,                SCCPDeviceUpdate,             SorceryMemoryCacheStaleObject,
  ConfbridgeUnmuteAction,       MessageSend,                  SCCPDndDevice,                StatusAction,
  ControlPlayback,              MixMonitor,                   SCCPHangupCall,               StopMixMonitor,
  CoreSettings,                 MixMonitorMute,               SCCPHoldCall,                 StopMonitor,
  CoreShowChannels,             ModuleCheck,                  SCCPLineForwardUpdate,        UnpauseMonitor,
  CoreStatus,                   ModuleLoad,                   SCCPListDevices,              UpdateConfig,
  CreateConfig,                 Monitor,                      SCCPListLines,                UserEventAction,
  DBDel,                        MuteAudio,                    SCCPMessageDevice,            VoicemailRefresh,
  DBDelTree,                    Originate,                    SCCPMessageDevices,           VoicemailUsersList,
  DBGet,                        Park,                         SCCPShowChannels,             WaitEvent,
}; //}}}

/*!
 * AMI semantic version structure. Used when AMI prompt line parsed.
 */
typedef struct AMIVer_ {
  unsigned short major; /*!< major */
  unsigned short minor; /*!< minor */
  unsigned short patch; /*!< patch */
} AMIVer;

/*!
 * AMI header structure.
 */
typedef struct AMIHeader_ {

  enum header_type    type;  /*!< AMI Header type. */

  struct str         *name;  /*!< AMI header name as string. */
  struct str         *value; /*!< AMI header value as string. */

  struct AMIHeader_   *next; /*!< Next AMI header pointer. Linked list element. */

} AMIHeader;

/*!
 * AMI packet structure.
 */
typedef struct AMIPacket_ {

  int             size;   /*!< Number of headers. */

  size_t          length; /*!< Total length of all headers as string. */

  enum pack_type  type;   /*!< AMI packet type: Action, Event etc. */

  AMIHeader       *head;  /*!< Linked list head pointer to AMI header. */
  AMIHeader       *tail;  /*!< Linked list tail pointer to AMI header. */

} AMIPacket;

/**
 * Inititate string.
 * @param buf   Char array to set with struct str.
 * @return pointer to new struct str
 */
struct str *str_set (const char *buf);

/**
 * Destroy string and free allocated memory.
 * @param s   String to destroy
 */
void str_destroy (struct str *s);

/**
 * Create new AMI header with given parameters.
 * Will allocated memory for AMIHeader and return pointer to it.
 * @param type    AMI header type
 * @param name    AMI header name
 * @param value   AMI header value
 * @return AMIHeader pointer to the new structure.
 */
AMIHeader *amiheader_create (enum header_type type, const char *name, const char *value);

/**
 * Destroy AMI header and free memory.
 * @param hdr   AMI header to destroy
 */
void amiheader_destroy (AMIHeader *hdr);

/**
 * Initiate AMIPacket and allocate memory.
 * AMI packet is implemented as linked list data structure.
 * @return AMIPacket pointer to the new structure.
 */
AMIPacket *amipack_init();

/**
 * Destroy AMI packet and free memory.
 * @param pack    AMI header to destroy
 */
void amipack_destroy(AMIPacket *pack);

/**
 * Append header to AMI packet.
 * Will create new AMI header using given type and value string.
 * New header will be appanded to the head of linked list.
 * @param pack      Pointer to AMI packet structure
 * @param hdr_type  AMI header type to create.
 * @param hdr_value AMI header value as string.
 * @return -1 if error or RV_SUCCESS
 */
int amipack_append(AMIPacket *pack, enum header_type hdr_type, const char *hdr_value);

/**
 * Append AMI header to AMI packet when type is unknown.
 * Will create new AMI header with type HDR_UNKNOWN and set provided name and value.
 * If AMI header is successfuly created, it will be appended to AMI packet.
 * @param pack      AMI packet structure pointer
 * @param name      AMI header name string
 * @param value     AMI header value as string
 * @return -1 if error or RV_SUCCESS
 */
int amipack_append_unknown(AMIPacket *pack, const char *name, const char *value);

/**
 * Append AMI header to packet.
 * @param pack      AMI packet structure pointer
 * @param header    AMI header structure pointer
 * @return -1 if error or RV_SUCCESS
 */
int amipack_list_append (AMIPacket *pack, AMIHeader *header);

/**
 * Convert AMIHeader to string.
 * @param hdr       AMI header structure pointer
 * @param buf       Header as string "Name: value\r\n"
 * @return header length
 */
int amiheader_to_str(AMIHeader *hdr, char *buf);

/**
 * Convert AMIPacket to string.
 * @param pack      AMI packet structure pointer
 * @return pointer to AMI packet as string
 */
struct str *amipack_to_str(AMIPacket *pack);

/**
 * Search header by header type. Will return value
 * if header in packet exists. Will return only first found
 * header value.
 * @param pack      AMI packet structure pointer
 * @param type      Header type to search
 * @return NULL or pointer to string struct which contains header value
 */
struct str *amiheader_value(AMIPacket *pack, enum header_type type);

/**
 * Search header by header name. Will return value
 * if header with given name in packet exists. Will return only
 * first found header value.
 * @param pack      AMI packet structure pointer
 * @param header_name Header name to search
 * @return NULL or pointer to string struct which contains header value
 */
struct str *amiheader_value_by_hdr_name(AMIPacket *pack, const char *header_name);

/**
 * Parse AMI protocol prompt string when user logged in.
 * Will set AMIver structure with parsed server AMI version.
 * Prompt header example: Asterisk Call Manager/1.1
 * @param packet    Packet received from server as bytes array.
 * @param version   AMIVer struct will be set when packet parsed
 * @return RV_SUCCESS or RV_FAIL
 */
int amiparse_prompt (const char *packet, AMIVer *version);

/**
 * Detect if packet is an AMI packet. AMI packets are terminated
 * by "\r\n\r\n" bytes sequence.
 * @param packet    Packet received from server as bytes array.
 * @param size      Bytes array size.
 * @return RV_SUCCESS or RV_FAIL
 */
int amiparse_stanza (const char *packet, int size);

/**
 * Get sub string from given string.
 * @param s       Source string
 * @param len     Length of string to extract
 * @param offset  Offset
 * @return pointer to extracted string.
 */
char *substr(const char* s, size_t len, size_t offset);

/**
 * Parse AMI packet to AMIPacket structure.
 * @param pack_str  Bytes array received from server.
 * @return AMIPacket pointer or NULL if AMI packet failed to parse.
 */
AMIPacket *amiparse_pack (const char *pack_str);

/**
 * AMI packet type name
 * @param type      AMI packet type.
 * @return AMI packet type name as string. Pointer to char array.
 */
const char *pack_type_str(enum pack_type type);

/**
 * Header name representation for given type.
 * @param type      AMI header type.
 * @return Header name as string. Pointer to char array.
 */
const char *header_name(enum header_type type);

#endif
