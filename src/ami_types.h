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
 * @file ami_types.h
 * @brief AMI (Asterisk Management Interface) types
 *
 * @author Stas Kobzar <stas.kobzar@modulis.ca>
 */

#ifndef __AMI_TYPES_H
#define __AMI_TYPES_H

// {{
#define AMI_HEADERS                 \
  MACRO_HDR(Account)                \
  MACRO_HDR(AccountCode)            \
  MACRO_HDR(ACL)                    \
  MACRO_HDR(Action)                 \
  MACRO_HDR(Address)                \
  MACRO_HDR(Address_IP)             \
  MACRO_HDR(Address_Port)           \
  MACRO_HDR(Agent)                  \
  MACRO_HDR(AMAflags)               \
  MACRO_HDR(AnswerTime)             \
  MACRO_HDR(Append)                 \
  MACRO_HDR(Application)            \
  MACRO_HDR(Async)                  \
  MACRO_HDR(AuthType)               \
  MACRO_HDR(BillableSeconds)        \
  MACRO_HDR(Bridgestate)            \
  MACRO_HDR(Bridgetype)             \
  MACRO_HDR(CallerID)               \
  MACRO_HDR(CallerID1)              \
  MACRO_HDR(CallerID2)              \
  MACRO_HDR(CallerIDName)           \
  MACRO_HDR(CallerIDNum)            \
  MACRO_HDR(Callgroup)              \
  MACRO_HDR(CallsTaken)             \
  MACRO_HDR(Cause)                  \
  MACRO_HDR(Cause_txt)              \
  MACRO_HDR(Channel)                \
  MACRO_HDR(Channel1)               \
  MACRO_HDR(Channel2)               \
  MACRO_HDR(ChannelState)           \
  MACRO_HDR(ChannelStateDesc)       \
  MACRO_HDR(ChannelType)            \
  MACRO_HDR(ChanObjectType)         \
  MACRO_HDR(CID_CallingPres)        \
  MACRO_HDR(CodecOrder)             \
  MACRO_HDR(Codecs)                 \
  MACRO_HDR(Command)                \
  MACRO_HDR(ConnectedLineName)      \
  MACRO_HDR(ConnectedLineNum)       \
  MACRO_HDR(Context)                \
  MACRO_HDR(Count)                  \
  MACRO_HDR(Data)                   \
  MACRO_HDR(Default_addr_IP)        \
  MACRO_HDR(Default_Username)       \
  MACRO_HDR(Destination)            \
  MACRO_HDR(DestinationChannel)     \
  MACRO_HDR(DestinationContext)     \
  MACRO_HDR(DestUniqueID)           \
  MACRO_HDR(DialStatus)             \
  MACRO_HDR(Dialstring)             \
  MACRO_HDR(Direction)              \
  MACRO_HDR(Disposition)            \
  MACRO_HDR(Domain)                 \
  MACRO_HDR(Duration)               \
  MACRO_HDR(Dynamic)                \
  MACRO_HDR(Endtime)                \
  MACRO_HDR(Event)                  \
  MACRO_HDR(EventList)              \
  MACRO_HDR(Events)                 \
  MACRO_HDR(Exten)                  \
  MACRO_HDR(Extension)              \
  MACRO_HDR(Family)                 \
  MACRO_HDR(File)                   \
  MACRO_HDR(FileName)               \
  MACRO_HDR(Format)                 \
  MACRO_HDR(From)                   \
  MACRO_HDR(Hint)                   \
  MACRO_HDR(Incominglimit)          \
  MACRO_HDR(Key)                    \
  MACRO_HDR(LastApplication)        \
  MACRO_HDR(LastCall)               \
  MACRO_HDR(LastData)               \
  MACRO_HDR(Link)                   \
  MACRO_HDR(ListItems)              \
  MACRO_HDR(LocalStationID)         \
  MACRO_HDR(Location)               \
  MACRO_HDR(Loginchan)              \
  MACRO_HDR(Logintime)              \
  MACRO_HDR(Mailbox)                \
  MACRO_HDR(MD5SecretExist)         \
  MACRO_HDR(Membership)             \
  MACRO_HDR(Message)                \
  MACRO_HDR(Mix)                    \
  MACRO_HDR(MOHSuggest)             \
  MACRO_HDR(NewMessages)            \
  MACRO_HDR(Newname)                \
  MACRO_HDR(ObjectName)             \
  MACRO_HDR(OldAccountCode)         \
  MACRO_HDR(OldMessages)            \
  MACRO_HDR(OldName)                \
  MACRO_HDR(Outgoinglimit)          \
  MACRO_HDR(PagesTransferred)       \
  MACRO_HDR(Paused)                 \
  MACRO_HDR(Peer)                   \
  MACRO_HDR(PeerStatus)             \
  MACRO_HDR(Penalty)                \
  MACRO_HDR(Pickupgroup)            \
  MACRO_HDR(Position)               \
  MACRO_HDR(Priority)               \
  MACRO_HDR(Privilege)              \
  MACRO_HDR(Queue)                  \
  MACRO_HDR(Reason)                 \
  MACRO_HDR(RegExpire)              \
  MACRO_HDR(RegExpiry)              \
  MACRO_HDR(RemoteStationID)        \
  MACRO_HDR(Resolution)             \
  MACRO_HDR(Response)               \
  MACRO_HDR(Restart)                \
  MACRO_HDR(Seconds)                \
  MACRO_HDR(Secret)                 \
  MACRO_HDR(SecretExist)            \
  MACRO_HDR(Shutdown)               \
  MACRO_HDR(SIP_AuthInsecure)       \
  MACRO_HDR(SIP_FromDomain)         \
  MACRO_HDR(SIP_FromUser)           \
  MACRO_HDR(SIPLastMsg)             \
  MACRO_HDR(SIP_NatSupport)         \
  MACRO_HDR(Source)                 \
  MACRO_HDR(SrcUniqueID)            \
  MACRO_HDR(StartTime)              \
  MACRO_HDR(State)                  \
  MACRO_HDR(Status)                 \
  MACRO_HDR(SubEvent)               \
  MACRO_HDR(Time)                   \
  MACRO_HDR(Timeout)                \
  MACRO_HDR(TransferRate)           \
  MACRO_HDR(UniqueID)               \
  MACRO_HDR(Uniqueid)               \
  MACRO_HDR(Uniqueid1)              \
  MACRO_HDR(Uniqueid2)              \
  MACRO_HDR(User)                   \
  MACRO_HDR(UserField)              \
  MACRO_HDR(Username)               \
  MACRO_HDR(Val)                    \
  MACRO_HDR(Value)                  \
  MACRO_HDR(Variable)               \
  MACRO_HDR(VoiceMailbox)           \
  MACRO_HDR(Waiting)                \

// }}

#endif
