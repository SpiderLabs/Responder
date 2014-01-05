#! /usr/bin/env python
# NBT-NS/LLMNR Responder
# Created by Laurent Gaffie
# Copyright (C) 2014 Trustwave Holdings, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import struct
from odict import OrderedDict

class Packet():
    fields = OrderedDict([
        ("data", ""),
    ])
    def __init__(self, **kw):
        self.fields = OrderedDict(self.__class__.fields)
        for k,v in kw.items():
            if callable(v):
                self.fields[k] = v(self.fields[k])
            else:
                self.fields[k] = v
    def __str__(self):
        return "".join(map(str, self.fields.values()))


class LDAPSearchDefaultPacket(Packet):
    fields = OrderedDict([
        ("ParserHeadASNID",   "\x30"),
        ("ParserHeadASNLen",  "\x0c"),
        ("MessageIDASNID",    "\x02"),
        ("MessageIDASNLen",   "\x01"),
        ("MessageIDASNStr",   "\x0f"),
        ("OpHeadASNID",       "\x65"),
        ("OpHeadASNIDLen",    "\x07"),
        ("SearchDoneSuccess", "\x0A\x01\x00\x04\x00\x04\x00"),#No Results.
    ])

class LDAPSearchSupportedCapabilitiesPacket(Packet):
    fields = OrderedDict([
        ("ParserHeadASNID",          "\x30"),
        ("ParserHeadASNLenOfLen",    "\x84"),
        ("ParserHeadASNLen",         "\x00\x00\x00\x7e"),#126
        ("MessageIDASNID",           "\x02"),
        ("MessageIDASNLen",          "\x01"),
        ("MessageIDASNStr",          "\x02"),
        ("OpHeadASNID",              "\x64"),
        ("OpHeadASNIDLenOfLen",      "\x84"),
        ("OpHeadASNIDLen",           "\x00\x00\x00\x75"),#117
        ("ObjectName",               "\x04\x00"),
        ("SearchAttribASNID",        "\x30"),
        ("SearchAttribASNLenOfLen",  "\x84"),
        ("SearchAttribASNLen",       "\x00\x00\x00\x6d"),#109
        ("SearchAttribASNID1",       "\x30"),
        ("SearchAttribASN1LenOfLen", "\x84"),
        ("SearchAttribASN1Len",      "\x00\x00\x00\x67"),#103
        ("SearchAttribASN2ID",       "\x04"),
        ("SearchAttribASN2Len",      "\x15"),#21
        ("SearchAttribASN2Str",      "supportedCapabilities"),
        ("SearchAttribASN3ID",       "\x31"),
        ("SearchAttribASN3LenOfLen", "\x84"),
        ("SearchAttribASN3Len",      "\x00\x00\x00\x4a"),
        ("SearchAttrib1ASNID",       "\x04"),
        ("SearchAttrib1ASNLen",      "\x16"),#22
        ("SearchAttrib1ASNStr",      "1.2.840.113556.1.4.800"),
        ("SearchAttrib2ASNID",       "\x04"),
        ("SearchAttrib2ASNLen",      "\x17"),#23
        ("SearchAttrib2ASNStr",      "1.2.840.113556.1.4.1670"),
        ("SearchAttrib3ASNID",       "\x04"),
        ("SearchAttrib3ASNLen",      "\x17"),#23
        ("SearchAttrib3ASNStr",      "1.2.840.113556.1.4.1791"),
        ("SearchDoneASNID",          "\x30"),
        ("SearchDoneASNLenOfLen",    "\x84"),
        ("SearchDoneASNLen",         "\x00\x00\x00\x10"),#16
        ("MessageIDASN2ID",          "\x02"),
        ("MessageIDASN2Len",         "\x01"),
        ("MessageIDASN2Str",         "\x02"),
        ("SearchDoneStr",            "\x65\x84\x00\x00\x00\x07\x0a\x01\x00\x04\x00\x04\x00"),
        ## No need to calculate anything this time, this packet is generic.
    ])

class LDAPSearchSupportedMechanismsPacket(Packet):
    fields = OrderedDict([
        ("ParserHeadASNID",          "\x30"),
        ("ParserHeadASNLenOfLen",    "\x84"),
        ("ParserHeadASNLen",         "\x00\x00\x00\x60"),#96
        ("MessageIDASNID",           "\x02"),
        ("MessageIDASNLen",          "\x01"),
        ("MessageIDASNStr",          "\x02"),
        ("OpHeadASNID",              "\x64"),
        ("OpHeadASNIDLenOfLen",      "\x84"),
        ("OpHeadASNIDLen",           "\x00\x00\x00\x57"),#87
        ("ObjectName",               "\x04\x00"),
        ("SearchAttribASNID",        "\x30"),
        ("SearchAttribASNLenOfLen",  "\x84"),
        ("SearchAttribASNLen",       "\x00\x00\x00\x4f"),#79
        ("SearchAttribASNID1",       "\x30"),
        ("SearchAttribASN1LenOfLen", "\x84"),
        ("SearchAttribASN1Len",      "\x00\x00\x00\x49"),#73
        ("SearchAttribASN2ID",       "\x04"),
        ("SearchAttribASN2Len",      "\x17"),#23
        ("SearchAttribASN2Str",      "supportedSASLMechanisms"),
        ("SearchAttribASN3ID",       "\x31"),
        ("SearchAttribASN3LenOfLen", "\x84"),
        ("SearchAttribASN3Len",      "\x00\x00\x00\x2a"),#42
        ("SearchAttrib1ASNID",       "\x04"),
        ("SearchAttrib1ASNLen",      "\x06"),#6
        ("SearchAttrib1ASNStr",      "GSSAPI"),
        ("SearchAttrib2ASNID",       "\x04"),
        ("SearchAttrib2ASNLen",      "\x0a"),#10
        ("SearchAttrib2ASNStr",      "GSS-SPNEGO"),
        ("SearchAttrib3ASNID",       "\x04"),
        ("SearchAttrib3ASNLen",      "\x08"),#8
        ("SearchAttrib3ASNStr",      "EXTERNAL"),
        ("SearchAttrib4ASNID",       "\x04"),
        ("SearchAttrib4ASNLen",      "\x0a"),#10
        ("SearchAttrib4ASNStr",      "DIGEST-MD5"),
        ("SearchDoneASNID",          "\x30"),
        ("SearchDoneASNLenOfLen",    "\x84"),
        ("SearchDoneASNLen",         "\x00\x00\x00\x10"),#16
        ("MessageIDASN2ID",          "\x02"),
        ("MessageIDASN2Len",         "\x01"),
        ("MessageIDASN2Str",         "\x02"),
        ("SearchDoneStr",            "\x65\x84\x00\x00\x00\x07\x0a\x01\x00\x04\x00\x04\x00"),
        ## No need to calculate anything this time, this packet is generic.
    ])

class LDAPNTLMChallenge(Packet):
    fields = OrderedDict([
        ("ParserHeadASNID",          "\x30"),
        ("ParserHeadASNLenOfLen",    "\x84"),
        ("ParserHeadASNLen",         "\x00\x00\x00\xD0"),#208
        ("MessageIDASNID",           "\x02"),
        ("MessageIDASNLen",          "\x01"),
        ("MessageIDASNStr",          "\x02"),
        ("OpHeadASNID",              "\x61"),
        ("OpHeadASNIDLenOfLen",      "\x84"),
        ("OpHeadASNIDLen",           "\x00\x00\x00\xc7"),#199
        ("Status",                   "\x0A"),
        ("StatusASNLen",             "\x01"),
        ("StatusASNStr",             "\x0e"), #In Progress.
        ("MatchedDN",                "\x04\x00"), #Null
        ("ErrorMessage",             "\x04\x00"), #Null
        ("SequenceHeader",           "\x87"),
        ("SequenceHeaderLenOfLen",   "\x81"),
        ("SequenceHeaderLen",        "\x82"), #188
        ("NTLMSSPSignature",         "NTLMSSP"),
        ("NTLMSSPSignatureNull",  "\x00"),
        ("NTLMSSPMessageType",    "\x02\x00\x00\x00"),
        ("NTLMSSPNtWorkstationLen","\x1e\x00"),
        ("NTLMSSPNtWorkstationMaxLen","\x1e\x00"),
        ("NTLMSSPNtWorkstationBuffOffset","\x38\x00\x00\x00"),
        ("NTLMSSPNtNegotiateFlags","\x15\x82\x89\xe2"),
        ("NTLMSSPNtServerChallenge","\x81\x22\x33\x34\x55\x46\xe7\x88"),
        ("NTLMSSPNtReserved","\x00\x00\x00\x00\x00\x00\x00\x00"),
        ("NTLMSSPNtTargetInfoLen","\x94\x00"),
        ("NTLMSSPNtTargetInfoMaxLen","\x94\x00"),
        ("NTLMSSPNtTargetInfoBuffOffset","\x56\x00\x00\x00"),
        ("NegTokenInitSeqMechMessageVersionHigh","\x05"),
        ("NegTokenInitSeqMechMessageVersionLow","\x02"),
        ("NegTokenInitSeqMechMessageVersionBuilt","\xce\x0e"),
        ("NegTokenInitSeqMechMessageVersionReserved","\x00\x00\x00"),
        ("NegTokenInitSeqMechMessageVersionNTLMType","\x0f"),
        ("NTLMSSPNtWorkstationName","SMB12"),
        ("NTLMSSPNTLMChallengeAVPairsId","\x02\x00"),
        ("NTLMSSPNTLMChallengeAVPairsLen","\x0a\x00"),
        ("NTLMSSPNTLMChallengeAVPairsUnicodeStr","smb12"),
        ("NTLMSSPNTLMChallengeAVPairs1Id","\x01\x00"),
        ("NTLMSSPNTLMChallengeAVPairs1Len","\x1e\x00"),
        ("NTLMSSPNTLMChallengeAVPairs1UnicodeStr","SERVER2008"), 
        ("NTLMSSPNTLMChallengeAVPairs2Id","\x04\x00"),
        ("NTLMSSPNTLMChallengeAVPairs2Len","\x1e\x00"),
        ("NTLMSSPNTLMChallengeAVPairs2UnicodeStr","smb12.local"), 
        ("NTLMSSPNTLMChallengeAVPairs3Id","\x03\x00"),
        ("NTLMSSPNTLMChallengeAVPairs3Len","\x1e\x00"),
        ("NTLMSSPNTLMChallengeAVPairs3UnicodeStr","SERVER2008.smb12.local"),
        ("NTLMSSPNTLMChallengeAVPairs5Id","\x05\x00"),
        ("NTLMSSPNTLMChallengeAVPairs5Len","\x04\x00"),
        ("NTLMSSPNTLMChallengeAVPairs5UnicodeStr","smb12.local"),
        ("NTLMSSPNTLMChallengeAVPairs6Id","\x00\x00"),
        ("NTLMSSPNTLMChallengeAVPairs6Len","\x00\x00"),
    ])

    def calculate(self):

        ##Convert strings to Unicode first...
        self.fields["NTLMSSPNtWorkstationName"] = self.fields["NTLMSSPNtWorkstationName"].encode('utf-16le')
        self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"] = self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"].encode('utf-16le')
        self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"] = self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"].encode('utf-16le')
        self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"] = self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"].encode('utf-16le')
        self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"] = self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"].encode('utf-16le')
        self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"] = self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"].encode('utf-16le')

        ###### Workstation Offset
        CalculateOffsetWorkstation = str(self.fields["NTLMSSPSignature"])+str(self.fields["NTLMSSPSignatureNull"])+str(self.fields["NTLMSSPMessageType"])+str(self.fields["NTLMSSPNtWorkstationLen"])+str(self.fields["NTLMSSPNtWorkstationMaxLen"])+str(self.fields["NTLMSSPNtWorkstationBuffOffset"])+str(self.fields["NTLMSSPNtNegotiateFlags"])+str(self.fields["NTLMSSPNtServerChallenge"])+str(self.fields["NTLMSSPNtReserved"])+str(self.fields["NTLMSSPNtTargetInfoLen"])+str(self.fields["NTLMSSPNtTargetInfoMaxLen"])+str(self.fields["NTLMSSPNtTargetInfoBuffOffset"])+str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])+str(self.fields["NegTokenInitSeqMechMessageVersionLow"])+str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])+str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])+str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])

        ###### AvPairs Offset
        CalculateLenAvpairs = str(self.fields["NTLMSSPNTLMChallengeAVPairsId"])+str(self.fields["NTLMSSPNTLMChallengeAVPairsLen"])+str(self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs1Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs1Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs2Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs2Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs3Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs3Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs5Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs5Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs6Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs6Len"])

        ###### LDAP Packet Len
        CalculatePacketLen = str(self.fields["MessageIDASNID"])+str(self.fields["MessageIDASNLen"])+str(self.fields["MessageIDASNStr"])+str(self.fields["OpHeadASNID"])+str(self.fields["OpHeadASNIDLenOfLen"])+str(self.fields["OpHeadASNIDLen"])+str(self.fields["Status"])+str(self.fields["StatusASNLen"])+str(self.fields["StatusASNStr"])+str(self.fields["MatchedDN"])+str(self.fields["ErrorMessage"])+str(self.fields["SequenceHeader"])+str(self.fields["SequenceHeaderLen"])+str(self.fields["SequenceHeaderLenOfLen"])+CalculateOffsetWorkstation+str(self.fields["NTLMSSPNtWorkstationName"])+CalculateLenAvpairs


        OperationPacketLen = str(self.fields["Status"])+str(self.fields["StatusASNLen"])+str(self.fields["StatusASNStr"])+str(self.fields["MatchedDN"])+str(self.fields["ErrorMessage"])+str(self.fields["SequenceHeader"])+str(self.fields["SequenceHeaderLen"])+str(self.fields["SequenceHeaderLenOfLen"])+CalculateOffsetWorkstation+str(self.fields["NTLMSSPNtWorkstationName"])+CalculateLenAvpairs

        NTLMMessageLen = CalculateOffsetWorkstation+str(self.fields["NTLMSSPNtWorkstationName"])+CalculateLenAvpairs

        ##### LDAP Len Calculation:
        self.fields["ParserHeadASNLen"] = struct.pack(">i", len(CalculatePacketLen))
        self.fields["OpHeadASNIDLen"] = struct.pack(">i", len(OperationPacketLen))
        self.fields["SequenceHeaderLen"] = struct.pack(">B", len(NTLMMessageLen))

        ##### Workstation Offset Calculation:
        self.fields["NTLMSSPNtWorkstationBuffOffset"] = struct.pack("<i", len(CalculateOffsetWorkstation))
        self.fields["NTLMSSPNtWorkstationLen"] = struct.pack("<h", len(str(self.fields["NTLMSSPNtWorkstationName"])))
        self.fields["NTLMSSPNtWorkstationMaxLen"] = struct.pack("<h", len(str(self.fields["NTLMSSPNtWorkstationName"])))

        ##### IvPairs Offset Calculation:
        self.fields["NTLMSSPNtTargetInfoBuffOffset"] = struct.pack("<i", len(CalculateOffsetWorkstation+str(self.fields["NTLMSSPNtWorkstationName"])))
        self.fields["NTLMSSPNtTargetInfoLen"] = struct.pack("<h", len(CalculateLenAvpairs))
        self.fields["NTLMSSPNtTargetInfoMaxLen"] = struct.pack("<h", len(CalculateLenAvpairs))
        ##### IvPair Calculation:
        self.fields["NTLMSSPNTLMChallengeAVPairs5Len"] = struct.pack("<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"])))
        self.fields["NTLMSSPNTLMChallengeAVPairs3Len"] = struct.pack("<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"])))
        self.fields["NTLMSSPNTLMChallengeAVPairs2Len"] = struct.pack("<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"])))
        self.fields["NTLMSSPNTLMChallengeAVPairs1Len"] = struct.pack("<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"])))
        self.fields["NTLMSSPNTLMChallengeAVPairsLen"] = struct.pack("<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"])))

