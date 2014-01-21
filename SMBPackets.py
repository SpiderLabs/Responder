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

#Calculate total SMB packet len.
def longueur(payload):
    length = struct.pack(">i", len(''.join(payload)))
    return length

#Set MID SMB Header field.
def midcalc(data):
    pack=data[34:36]
    return pack

#Set UID SMB Header field.
def uidcalc(data):
    pack=data[32:34]
    return pack

#Set PID SMB Header field.
def pidcalc(data):
    pack=data[30:32]
    return pack

#Set TID SMB Header field.
def tidcalc(data):
    pack=data[28:30]
    return pack


##################################################################################
class SMBHeader(Packet):
    fields = OrderedDict([
        ("proto", "\xff\x53\x4d\x42"),
        ("cmd", "\x72"),
        ("errorcode", "\x00\x00\x00\x00" ),
        ("flag1", "\x00"),
        ("flag2", "\x00\x00"),
        ("pidhigh", "\x00\x00"),
        ("signature", "\x00\x00\x00\x00\x00\x00\x00\x00"),
        ("reserved", "\x00\x00"),
        ("tid", "\x00\x00"),
        ("pid", "\x00\x00"),
        ("uid", "\x00\x00"),
        ("mid", "\x00\x00"),
    ])
##################################################################################
#SMB Negotiate Answer LM packet.
class SMBNegoAnsLM(Packet):
    fields = OrderedDict([
        ("Wordcount",    "\x11"),
        ("Dialect",      ""),
        ("Securitymode", "\x03"),
        ("MaxMpx",       "\x32\x00"),
        ("MaxVc",        "\x01\x00"),
        ("Maxbuffsize",  "\x04\x41\x00\x00"),
        ("Maxrawbuff",   "\x00\x00\x01\x00"),
        ("Sessionkey",   "\x00\x00\x00\x00"),
        ("Capabilities", "\xfc\x3e\x01\x00"),
        ("Systemtime",   "\x84\xd6\xfb\xa3\x01\x35\xcd\x01"),
        ("Srvtimezone",  "\x2c\x01"),
        ("Keylength",    "\x08"),
        ("Bcc",          "\x10\x00"),
        ("Key",          ""),
        ("Domain",       "SMB"),
        ("DomainNull",   "\x00\x00"),
        ("Server",       "SMB-TOOLKIT"),
        ("ServerNull",   "\x00\x00"),
    ])

    def calculate(self):
        ##Convert first..
        self.fields["Domain"] = self.fields["Domain"].encode('utf-16le')
        self.fields["Server"] = self.fields["Server"].encode('utf-16le')
        ##Then calculate.
        CompleteBCCLen =  str(self.fields["Key"])+str(self.fields["Domain"])+str(self.fields["DomainNull"])+str(self.fields["Server"])+str(self.fields["ServerNull"])
        self.fields["Bcc"] = struct.pack("<h",len(CompleteBCCLen))
        self.fields["Keylength"] = struct.pack("<h",len(self.fields["Key"]))[0]
##################################################################################
#SMB Negotiate Answer LM packet.
class SMBNegoAns(Packet):
    fields = OrderedDict([
        ("Wordcount",    "\x11"),
        ("Dialect",      ""),
        ("Securitymode", "\x03"),
        ("MaxMpx",       "\x32\x00"),
        ("MaxVc",        "\x01\x00"),
        ("MaxBuffSize",  "\x04\x41\x00\x00"),
        ("MaxRawBuff",   "\x00\x00\x01\x00"),
        ("SessionKey",   "\x00\x00\x00\x00"),
        ("Capabilities", "\xfd\xf3\x01\x80"),
        ("SystemTime",   "\x84\xd6\xfb\xa3\x01\x35\xcd\x01"),
        ("SrvTimeZone",  "\xf0\x00"),
        ("KeyLen",    "\x00"),
        ("Bcc",          "\x57\x00"),
        ("Guid",         "\xc8\x27\x3d\xfb\xd4\x18\x55\x4f\xb2\x40\xaf\xd7\x61\x73\x75\x3b"),
        ("InitContextTokenASNId",     "\x60"),
        ("InitContextTokenASNLen",    "\x5b"),
        ("ThisMechASNId",             "\x06"),
        ("ThisMechASNLen",            "\x06"),
        ("ThisMechASNStr",            "\x2b\x06\x01\x05\x05\x02"),
        ("SpNegoTokenASNId",          "\xA0"),
        ("SpNegoTokenASNLen",         "\x51"),
        ("NegTokenASNId",             "\x30"),
        ("NegTokenASNLen",            "\x4f"),
        ("NegTokenTag0ASNId",         "\xA0"),
        ("NegTokenTag0ASNLen",        "\x30"),
        ("NegThisMechASNId",          "\x30"),
        ("NegThisMechASNLen",         "\x2e"),
        ("NegThisMech4ASNId",         "\x06"),
        ("NegThisMech4ASNLen",        "\x09"),
        ("NegThisMech4ASNStr",        "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"),
        ("NegTokenTag3ASNId",         "\xA3"),
        ("NegTokenTag3ASNLen",        "\x1b"),
        ("NegHintASNId",              "\x30"),
        ("NegHintASNLen",             "\x19"),
        ("NegHintTag0ASNId",          "\xa0"),
        ("NegHintTag0ASNLen",         "\x17"),
        ("NegHintFinalASNId",         "\x1b"), 
        ("NegHintFinalASNLen",        "\x15"),
        ("NegHintFinalASNStr",        "server2008$@SMB.LOCAL"),
##  END

    ])

    def calculate(self):

        CompleteBCCLen1 =  str(self.fields["Guid"])+str(self.fields["InitContextTokenASNId"])+str(self.fields["InitContextTokenASNLen"])+str(self.fields["ThisMechASNId"])+str(self.fields["ThisMechASNLen"])+str(self.fields["ThisMechASNStr"])+str(self.fields["SpNegoTokenASNId"])+str(self.fields["SpNegoTokenASNLen"])+str(self.fields["NegTokenASNId"])+str(self.fields["NegTokenASNLen"])+str(self.fields["NegTokenTag0ASNId"])+str(self.fields["NegTokenTag0ASNLen"])+str(self.fields["NegThisMechASNId"])+str(self.fields["NegThisMechASNLen"])+str(self.fields["NegThisMech4ASNId"])+str(self.fields["NegThisMech4ASNLen"])+str(self.fields["NegThisMech4ASNStr"])+str(self.fields["NegTokenTag3ASNId"])+str(self.fields["NegTokenTag3ASNLen"])+str(self.fields["NegHintASNId"])+str(self.fields["NegHintASNLen"])+str(self.fields["NegHintTag0ASNId"])+str(self.fields["NegHintTag0ASNLen"])+str(self.fields["NegHintFinalASNId"])+str(self.fields["NegHintFinalASNLen"])+str(self.fields["NegHintFinalASNStr"])

        AsnLenStart = str(self.fields["ThisMechASNId"])+str(self.fields["ThisMechASNLen"])+str(self.fields["ThisMechASNStr"])+str(self.fields["SpNegoTokenASNId"])+str(self.fields["SpNegoTokenASNLen"])+str(self.fields["NegTokenASNId"])+str(self.fields["NegTokenASNLen"])+str(self.fields["NegTokenTag0ASNId"])+str(self.fields["NegTokenTag0ASNLen"])+str(self.fields["NegThisMechASNId"])+str(self.fields["NegThisMechASNLen"])+str(self.fields["NegThisMech4ASNId"])+str(self.fields["NegThisMech4ASNLen"])+str(self.fields["NegThisMech4ASNStr"])+str(self.fields["NegTokenTag3ASNId"])+str(self.fields["NegTokenTag3ASNLen"])+str(self.fields["NegHintASNId"])+str(self.fields["NegHintASNLen"])+str(self.fields["NegHintTag0ASNId"])+str(self.fields["NegHintTag0ASNLen"])+str(self.fields["NegHintFinalASNId"])+str(self.fields["NegHintFinalASNLen"])+str(self.fields["NegHintFinalASNStr"])

        AsnLen2 = str(self.fields["NegTokenASNId"])+str(self.fields["NegTokenASNLen"])+str(self.fields["NegTokenTag0ASNId"])+str(self.fields["NegTokenTag0ASNLen"])+str(self.fields["NegThisMechASNId"])+str(self.fields["NegThisMechASNLen"])+str(self.fields["NegThisMech4ASNId"])+str(self.fields["NegThisMech4ASNLen"])+str(self.fields["NegThisMech4ASNStr"])+str(self.fields["NegTokenTag3ASNId"])+str(self.fields["NegTokenTag3ASNLen"])+str(self.fields["NegHintASNId"])+str(self.fields["NegHintASNLen"])+str(self.fields["NegHintTag0ASNId"])+str(self.fields["NegHintTag0ASNLen"])+str(self.fields["NegHintFinalASNId"])+str(self.fields["NegHintFinalASNLen"])+str(self.fields["NegHintFinalASNStr"])

        MechTypeLen = str(self.fields["NegThisMechASNId"])+str(self.fields["NegThisMechASNLen"])+str(self.fields["NegThisMech4ASNId"])+str(self.fields["NegThisMech4ASNLen"])+str(self.fields["NegThisMech4ASNStr"])

        Tag3Len = str(self.fields["NegHintASNId"])+str(self.fields["NegHintASNLen"])+str(self.fields["NegHintTag0ASNId"])+str(self.fields["NegHintTag0ASNLen"])+str(self.fields["NegHintFinalASNId"])+str(self.fields["NegHintFinalASNLen"])+str(self.fields["NegHintFinalASNStr"])

        self.fields["Bcc"] = struct.pack("<h",len(CompleteBCCLen1))
        self.fields["InitContextTokenASNLen"] = struct.pack("<B", len(AsnLenStart))
        self.fields["ThisMechASNLen"] = struct.pack("<B", len(str(self.fields["ThisMechASNStr"])))
        self.fields["SpNegoTokenASNLen"] = struct.pack("<B", len(AsnLen2))
        self.fields["NegTokenASNLen"] = struct.pack("<B", len(AsnLen2)-2)
        self.fields["NegTokenTag0ASNLen"] = struct.pack("<B", len(MechTypeLen))
        self.fields["NegThisMechASNLen"] = struct.pack("<B", len(MechTypeLen)-2)
        self.fields["NegThisMech4ASNLen"] = struct.pack("<B", len(str(self.fields["NegThisMech4ASNStr"])))
        self.fields["NegTokenTag3ASNLen"] = struct.pack("<B", len(Tag3Len))
        self.fields["NegHintASNLen"] = struct.pack("<B", len(Tag3Len)-2)
        self.fields["NegHintTag0ASNLen"] = struct.pack("<B", len(Tag3Len)-4)
        self.fields["NegHintFinalASNLen"] = struct.pack("<B", len(str(self.fields["NegHintFinalASNStr"])))

################################################################################

class SMBSession1Data(Packet):
    fields = OrderedDict([
        ("Wordcount",             "\x04"),
        ("AndXCommand",           "\xff"),
        ("Reserved",              "\x00"),
        ("Andxoffset",            "\x5f\x01"),
        ("Action",                "\x00\x00"),
        ("SecBlobLen",            "\xea\x00"),
        ("Bcc",                   "\x34\x01"),
        ("ChoiceTagASNId",        "\xa1"), 
        ("ChoiceTagASNLenOfLen",  "\x81"), 
        ("ChoiceTagASNIdLen",     "\x00"),
        ("NegTokenTagASNId",      "\x30"),
        ("NegTokenTagASNLenOfLen","\x81"),
        ("NegTokenTagASNIdLen",   "\x00"),
        ("Tag0ASNId",             "\xA0"),
        ("Tag0ASNIdLen",          "\x03"),
        ("NegoStateASNId",        "\x0A"),
        ("NegoStateASNLen",       "\x01"),
        ("NegoStateASNValue",     "\x01"),
        ("Tag1ASNId",             "\xA1"),
        ("Tag1ASNIdLen",          "\x0c"),
        ("Tag1ASNId2",            "\x06"),
        ("Tag1ASNId2Len",         "\x0A"),
        ("Tag1ASNId2Str",         "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"),
        ("Tag2ASNId",             "\xA2"),
        ("Tag2ASNIdLenOfLen",     "\x81"),
        ("Tag2ASNIdLen",          "\xED"),
        ("Tag3ASNId",             "\x04"),
        ("Tag3ASNIdLenOfLen",     "\x81"),
        ("Tag3ASNIdLen",          "\xEA"),
        ("NTLMSSPSignature",      "NTLMSSP"),
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
        ("NTLMSSPNTLMPadding",             ""),
        ("NativeOs","Windows Server 2003 3790 Service Pack 2"),                           
        ("NativeOsTerminator","\x00\x00"),
        ("NativeLAN", "Windows Server 2003 5.2"),
        ("NativeLANTerminator","\x00\x00"),
    ])


    def calculate(self):

        ##Convert strings to Unicode first...
        self.fields["NTLMSSPNtWorkstationName"] = self.fields["NTLMSSPNtWorkstationName"].encode('utf-16le')
        self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"] = self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"].encode('utf-16le')
        self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"] = self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"].encode('utf-16le')
        self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"] = self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"].encode('utf-16le')
        self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"] = self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"].encode('utf-16le')
        self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"] = self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"].encode('utf-16le')
        self.fields["NativeOs"] = self.fields["NativeOs"].encode('utf-16le')
        self.fields["NativeLAN"] = self.fields["NativeLAN"].encode('utf-16le')

        ###### SecBlobLen Calc:
        AsnLen= str(self.fields["ChoiceTagASNId"])+str(self.fields["ChoiceTagASNLenOfLen"])+str(self.fields["ChoiceTagASNIdLen"])+str(self.fields["NegTokenTagASNId"])+str(self.fields["NegTokenTagASNLenOfLen"])+str(self.fields["NegTokenTagASNIdLen"])+str(self.fields["Tag0ASNId"])+str(self.fields["Tag0ASNIdLen"])+str(self.fields["NegoStateASNId"])+str(self.fields["NegoStateASNLen"])+str(self.fields["NegoStateASNValue"])+str(self.fields["Tag1ASNId"])+str(self.fields["Tag1ASNIdLen"])+str(self.fields["Tag1ASNId2"])+str(self.fields["Tag1ASNId2Len"])+str(self.fields["Tag1ASNId2Str"])+str(self.fields["Tag2ASNId"])+str(self.fields["Tag2ASNIdLenOfLen"])+str(self.fields["Tag2ASNIdLen"])+str(self.fields["Tag3ASNId"])+str(self.fields["Tag3ASNIdLenOfLen"])+str(self.fields["Tag3ASNIdLen"])

        CalculateSecBlob = str(self.fields["NTLMSSPSignature"])+str(self.fields["NTLMSSPSignatureNull"])+str(self.fields["NTLMSSPMessageType"])+str(self.fields["NTLMSSPNtWorkstationLen"])+str(self.fields["NTLMSSPNtWorkstationMaxLen"])+str(self.fields["NTLMSSPNtWorkstationBuffOffset"])+str(self.fields["NTLMSSPNtNegotiateFlags"])+str(self.fields["NTLMSSPNtServerChallenge"])+str(self.fields["NTLMSSPNtReserved"])+str(self.fields["NTLMSSPNtTargetInfoLen"])+str(self.fields["NTLMSSPNtTargetInfoMaxLen"])+str(self.fields["NTLMSSPNtTargetInfoBuffOffset"])+str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])+str(self.fields["NegTokenInitSeqMechMessageVersionLow"])+str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])+str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])+str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])+str(self.fields["NTLMSSPNtWorkstationName"])+str(self.fields["NTLMSSPNTLMChallengeAVPairsId"])+str(self.fields["NTLMSSPNTLMChallengeAVPairsLen"])+str(self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs1Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs1Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs2Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs2Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs3Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs3Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs5Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs5Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs6Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs6Len"])

        ##### Bcc len
        BccLen = AsnLen+CalculateSecBlob+str(self.fields["NTLMSSPNTLMPadding"])+str(self.fields["NativeOs"])+str(self.fields["NativeOsTerminator"])+str(self.fields["NativeLAN"])+str(self.fields["NativeLANTerminator"])
        #SecBlobLen
        self.fields["SecBlobLen"] = struct.pack("<h", len(AsnLen+CalculateSecBlob))
        self.fields["Bcc"] = struct.pack("<h", len(BccLen))
        self.fields["ChoiceTagASNIdLen"] = struct.pack(">B", len(AsnLen+CalculateSecBlob)-3)
        self.fields["NegTokenTagASNIdLen"] = struct.pack(">B", len(AsnLen+CalculateSecBlob)-6)
        self.fields["Tag1ASNIdLen"] = struct.pack(">B", len(str(self.fields["Tag1ASNId2"])+str(self.fields["Tag1ASNId2Len"])+str(self.fields["Tag1ASNId2Str"])))
        self.fields["Tag1ASNId2Len"] = struct.pack(">B", len(str(self.fields["Tag1ASNId2Str"])))
        self.fields["Tag2ASNIdLen"] = struct.pack(">B", len(CalculateSecBlob+str(self.fields["Tag3ASNId"])+str(self.fields["Tag3ASNIdLenOfLen"])+str(self.fields["Tag3ASNIdLen"])))
        self.fields["Tag3ASNIdLen"] = struct.pack(">B", len(CalculateSecBlob))

        ###### Andxoffset calculation.
        CalculateCompletePacket = str(self.fields["Wordcount"])+str(self.fields["AndXCommand"])+str(self.fields["Reserved"])+str(self.fields["Andxoffset"])+str(self.fields["Action"])+str(self.fields["SecBlobLen"])+str(self.fields["Bcc"])+BccLen

        self.fields["Andxoffset"] = struct.pack("<h", len(CalculateCompletePacket)+32)
        ###### Workstation Offset
        CalculateOffsetWorkstation = str(self.fields["NTLMSSPSignature"])+str(self.fields["NTLMSSPSignatureNull"])+str(self.fields["NTLMSSPMessageType"])+str(self.fields["NTLMSSPNtWorkstationLen"])+str(self.fields["NTLMSSPNtWorkstationMaxLen"])+str(self.fields["NTLMSSPNtWorkstationBuffOffset"])+str(self.fields["NTLMSSPNtNegotiateFlags"])+str(self.fields["NTLMSSPNtServerChallenge"])+str(self.fields["NTLMSSPNtReserved"])+str(self.fields["NTLMSSPNtTargetInfoLen"])+str(self.fields["NTLMSSPNtTargetInfoMaxLen"])+str(self.fields["NTLMSSPNtTargetInfoBuffOffset"])+str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])+str(self.fields["NegTokenInitSeqMechMessageVersionLow"])+str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])+str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])+str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])

        ###### AvPairs Offset
        CalculateLenAvpairs = str(self.fields["NTLMSSPNTLMChallengeAVPairsId"])+str(self.fields["NTLMSSPNTLMChallengeAVPairsLen"])+str(self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs1Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs1Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs2Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs2Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs3Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs3Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs5Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs5Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs6Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs6Len"])

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

##################################################################################

class SMBSession2Accept(Packet):
    fields = OrderedDict([
        ("Wordcount",             "\x04"),
        ("AndXCommand",           "\xff"),
        ("Reserved",              "\x00"),
        ("Andxoffset",            "\xb4\x00"),
        ("Action",                "\x00\x00"),
        ("SecBlobLen",            "\x09\x00"),
        ("Bcc",                   "\x89\x01"),
        ("SSPIAccept","\xa1\x07\x30\x05\xa0\x03\x0a\x01\x00"),
        ("NativeOs","Windows Server 2003 3790 Service Pack 2"),                           
        ("NativeOsTerminator","\x00\x00"),
        ("NativeLAN", "Windows Server 2003 5.2"),
        ("NativeLANTerminator","\x00\x00"),
    ])
    def calculate(self):
        self.fields["NativeOs"] = self.fields["NativeOs"].encode('utf-16le')
        self.fields["NativeLAN"] = self.fields["NativeLAN"].encode('utf-16le')
        BccLen = str(self.fields["SSPIAccept"])+str(self.fields["NativeOs"])+str(self.fields["NativeOsTerminator"])+str(self.fields["NativeLAN"])+str(self.fields["NativeLANTerminator"])
        self.fields["Bcc"] = struct.pack("<h", len(BccLen))

class SMBSessEmpty(Packet):
    fields = OrderedDict([
        ("Empty",       "\x00\x00\x00"),
    ])

class SMBTreeData(Packet):
    fields = OrderedDict([
        ("Wordcount", "\x07"),
        ("AndXCommand", "\xff"),
        ("Reserved","\x00" ),
        ("Andxoffset", "\xbd\x00"),
        ("OptionalSupport","\x00\x00"),
        ("MaxShareAccessRight","\x00\x00\x00\x00"),
        ("GuestShareAccessRight","\x00\x00\x00\x00"),
        ("Bcc", "\x94\x00"),
        ("Service", "IPC"),
        ("ServiceTerminator","\x00\x00\x00\x00"),                           
    ])


    def calculate(self):
        #Complete Packet Len
        CompletePacket= str(self.fields["Wordcount"])+str(self.fields["AndXCommand"])+str(self.fields["Reserved"])+str(self.fields["Andxoffset"])+str(self.fields["OptionalSupport"])+str(self.fields["MaxShareAccessRight"])+str(self.fields["GuestShareAccessRight"])+str(self.fields["Bcc"])+str(self.fields["Service"])+str(self.fields["ServiceTerminator"])
        ## AndXOffset
        self.fields["Andxoffset"] = struct.pack("<H", len(CompletePacket)+32)
        ## BCC Len Calc
        BccLen= str(self.fields["Service"])+str(self.fields["ServiceTerminator"])
        self.fields["Bcc"] = struct.pack("<H", len(BccLen))

# SMB Session/Tree Answer.
class SMBSessTreeAns(Packet):
    fields = OrderedDict([
        ("Wordcount",       "\x03"),
        ("Command",         "\x75"), 
        ("Reserved",        "\x00"),
        ("AndXoffset",      "\x4e\x00"),
        ("Action",          "\x01\x00"),
        ("Bcc",             "\x25\x00"),
        ("NativeOs",        "Windows 5.1"),
        ("NativeOsNull",    "\x00"),
        ("NativeLan",       "Windows 2000 LAN Manager"),
        ("NativeLanNull",   "\x00"),
        ("WordcountTree",   "\x03"),
        ("AndXCommand",     "\xff"),
        ("Reserved1",       "\x00"),
        ("AndxOffset",      "\x00\x00"),
        ("OptionalSupport", "\x01\x00"),
        ("Bcc2",            "\x08\x00"),
        ("Service",         "A:"),
        ("ServiceNull",     "\x00"),
        ("FileSystem",      "NTFS"),
        ("FileSystemNull",  "\x00"),

    ])

    def calculate(self):
        ##AndxOffset
        CalculateCompletePacket = str(self.fields["Wordcount"])+str(self.fields["Command"])+str(self.fields["Reserved"])+str(self.fields["AndXoffset"])+str(self.fields["Action"])+str(self.fields["Bcc"])+str(self.fields["NativeOs"])+str(self.fields["NativeOsNull"])+str(self.fields["NativeLan"])+str(self.fields["NativeLanNull"])
        self.fields["AndXoffset"] = struct.pack("<i", len(CalculateCompletePacket)+32)[:2]
        ##BCC 1 and 2
        CompleteBCCLen =  str(self.fields["NativeOs"])+str(self.fields["NativeOsNull"])+str(self.fields["NativeLan"])+str(self.fields["NativeLanNull"])
        self.fields["Bcc"] = struct.pack("<h",len(CompleteBCCLen))
        CompleteBCC2Len = str(self.fields["Service"])+str(self.fields["ServiceNull"])+str(self.fields["FileSystem"])+str(self.fields["FileSystemNull"])
        self.fields["Bcc2"] = struct.pack("<h",len(CompleteBCC2Len))
