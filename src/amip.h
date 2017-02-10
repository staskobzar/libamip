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

struct str {
  char *buf;
  int  len;
};

enum pack_type {
  AMI_UNKNOWN, AMI_PROMPT, AMI_ACTION, AMI_EVENT, AMI_RESPONSE
};

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
  ChannelType,             Key,                     RegExpiry,               ActionID
}; //}}}

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
 * AMI header structure.
 */
typedef struct AMIHeader_ {

  enum header_type    type;

  struct str         name;
  struct str         value;

  struct AMIHeader_   *next;

} AMIHeader;

/*!
 * AMI packet structure.
 */
typedef struct AMIPacket_ {

  int             size;   /*<! Number of headers. */

  int             length;

  enum pack_type  type;

  AMIHeader       *head;
  AMIHeader       *tail;

} AMIPacket;

void str_init(struct str *str, int size);

void str_destroy (struct str *s);

AMIHeader *amiheader_create (enum header_type type, const char *name, const char *value);

void amiheader_destroy (AMIHeader *hdr);

void amipack_init(AMIPacket *pack, enum pack_type type);

void amipack_destroy(AMIPacket *pack);

int amipack_append(AMIPacket *pack, enum header_type hdr_type, const char *hdr_value);

int amiheader_to_str(AMIHeader *hdr, struct str *s);

int amipack_to_str(AMIPacket *pack, struct str *s);

#endif
