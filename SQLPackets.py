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

#MS-SQL Pre-login packet class
class MSSQLPreLoginAnswer(Packet):
    fields = OrderedDict([
        ("PacketType",       "\x04"),
        ("Status",           "\x01"), 
        ("Len",              "\x00\x25"),
        ("SPID",             "\x00\x00"),
        ("PacketID",         "\x01"),
        ("Window",           "\x00"),
        ("TokenType",        "\x00"),
        ("VersionOffset",    "\x00\x15"),
        ("VersionLen",       "\x00\x06"),
        ("TokenType1",       "\x01"),
        ("EncryptionOffset", "\x00\x1b"),
        ("EncryptionLen",    "\x00\x01"),
        ("TokenType2",       "\x02"),
        ("InstOptOffset",    "\x00\x1c"),
        ("InstOptLen",       "\x00\x01"),
        ("TokenTypeThrdID",  "\x03"),
        ("ThrdIDOffset",     "\x00\x1d"),
        ("ThrdIDLen",        "\x00\x00"),
        ("ThrdIDTerminator", "\xff"),
        ("VersionStr",       "\x09\x00\x0f\xc3"),
        ("SubBuild",         "\x00\x00"),
        ("EncryptionStr",    "\x02"),
        ("InstOptStr",       "\x00"),
        ]) 

    def calculate(self):
        CalculateCompletePacket = str(self.fields["PacketType"])+str(self.fields["Status"])+str(self.fields["Len"])+str(self.fields["SPID"])+str(self.fields["PacketID"])+str(self.fields["Window"])+str(self.fields["TokenType"])+str(self.fields["VersionOffset"])+str(self.fields["VersionLen"])+str(self.fields["TokenType1"])+str(self.fields["EncryptionOffset"])+str(self.fields["EncryptionLen"])+str(self.fields["TokenType2"])+str(self.fields["InstOptOffset"])+str(self.fields["InstOptLen"])+str(self.fields["TokenTypeThrdID"])+str(self.fields["ThrdIDOffset"])+str(self.fields["ThrdIDLen"])+str(self.fields["ThrdIDTerminator"])+str(self.fields["VersionStr"])+str(self.fields["SubBuild"])+str(self.fields["EncryptionStr"])+str(self.fields["InstOptStr"])

        VersionOffset = str(self.fields["TokenType"])+str(self.fields["VersionOffset"])+str(self.fields["VersionLen"])+str(self.fields["TokenType1"])+str(self.fields["EncryptionOffset"])+str(self.fields["EncryptionLen"])+str(self.fields["TokenType2"])+str(self.fields["InstOptOffset"])+str(self.fields["InstOptLen"])+str(self.fields["TokenTypeThrdID"])+str(self.fields["ThrdIDOffset"])+str(self.fields["ThrdIDLen"])+str(self.fields["ThrdIDTerminator"])

        EncryptionOffset = VersionOffset+str(self.fields["VersionStr"])+str(self.fields["SubBuild"])

        InstOpOffset = EncryptionOffset+str(self.fields["EncryptionStr"])
         
        ThrdIDOffset = InstOpOffset+str(self.fields["InstOptStr"])

        self.fields["Len"] = struct.pack(">h",len(CalculateCompletePacket))
        #Version
        self.fields["VersionLen"] = struct.pack(">h",len(self.fields["VersionStr"]+self.fields["SubBuild"]))
        self.fields["VersionOffset"] = struct.pack(">h",len(VersionOffset))
        #Encryption
        self.fields["EncryptionLen"] = struct.pack(">h",len(self.fields["EncryptionStr"]))
        self.fields["EncryptionOffset"] = struct.pack(">h",len(EncryptionOffset))
        #InstOpt
        self.fields["InstOptLen"] = struct.pack(">h",len(self.fields["InstOptStr"]))
        self.fields["EncryptionOffset"] = struct.pack(">h",len(InstOpOffset))
        #ThrdIDOffset
        self.fields["ThrdIDOffset"] = struct.pack(">h",len(ThrdIDOffset))

#MS-SQL NTLM Negotiate packet class
class MSSQLNTLMChallengeAnswer(Packet):
    fields = OrderedDict([
        ("PacketType",       "\x04"), 
        ("Status",           "\x01"),
        ("Len",              "\x00\xc7"),
        ("SPID",             "\x00\x00"),
        ("PacketID",         "\x01"),
        ("Window",           "\x00"),
        ("TokenType",        "\xed"),
        ("SSPIBuffLen",      "\xbc\x00"),
        ("Signature",        "NTLMSSP"),
        ("SignatureNull",    "\x00"),
        ("MessageType",      "\x02\x00\x00\x00"),
        ("TargetNameLen",    "\x06\x00"),
        ("TargetNameMaxLen", "\x06\x00"),
        ("TargetNameOffset", "\x38\x00\x00\x00"),
        ("NegoFlags",        "\x05\x02\x89\xa2"),
        ("ServerChallenge",  ""),
        ("Reserved",         "\x00\x00\x00\x00\x00\x00\x00\x00"),
        ("TargetInfoLen",    "\x7e\x00"),
        ("TargetInfoMaxLen", "\x7e\x00"),
        ("TargetInfoOffset", "\x3e\x00\x00\x00"),
        ("NTLMOsVersion",    "\x05\x02\xce\x0e\x00\x00\x00\x0f"),
        ("TargetNameStr",    "SMB"),
        ("Av1",              "\x02\x00"),#nbt name
        ("Av1Len",           "\x06\x00"),
        ("Av1Str",           "SMB"),
        ("Av2",              "\x01\x00"),#Server name
        ("Av2Len",           "\x14\x00"),
        ("Av2Str",           "SMB-TOOLKIT"),
        ("Av3",              "\x04\x00"),#Full Domain name
        ("Av3Len",           "\x12\x00"),
        ("Av3Str",           "smb.local"),
        ("Av4",              "\x03\x00"),#Full machine domain name
        ("Av4Len",           "\x28\x00"),
        ("Av4Str",           "server2003.smb.local"),
        ("Av5",              "\x05\x00"),#Domain Forest Name
        ("Av5Len",           "\x12\x00"),
        ("Av5Str",           "smb.local"),
        ("Av6",              "\x00\x00"),#AvPairs Terminator
        ("Av6Len",           "\x00\x00"),
        ]) 

    def calculate(self):
        ##First convert to uni
        self.fields["TargetNameStr"] = self.fields["TargetNameStr"].encode('utf-16le')
        self.fields["Av1Str"] = self.fields["Av1Str"].encode('utf-16le')
        self.fields["Av2Str"] = self.fields["Av2Str"].encode('utf-16le')
        self.fields["Av3Str"] = self.fields["Av3Str"].encode('utf-16le')
        self.fields["Av4Str"] = self.fields["Av4Str"].encode('utf-16le')
        self.fields["Av5Str"] = self.fields["Av5Str"].encode('utf-16le')
        ##Then calculate

        CalculateCompletePacket = str(self.fields["PacketType"])+str(self.fields["Status"])+str(self.fields["Len"])+str(self.fields["SPID"])+str(self.fields["PacketID"])+str(self.fields["Window"])+str(self.fields["TokenType"])+str(self.fields["SSPIBuffLen"])+str(self.fields["Signature"])+str(self.fields["SignatureNull"])+str(self.fields["MessageType"])+str(self.fields["TargetNameLen"])+str(self.fields["TargetNameMaxLen"])+str(self.fields["TargetNameOffset"])+str(self.fields["NegoFlags"])+str(self.fields["ServerChallenge"])+str(self.fields["Reserved"])+str(self.fields["TargetInfoLen"])+str(self.fields["TargetInfoMaxLen"])+str(self.fields["TargetInfoOffset"])+str(self.fields["NTLMOsVersion"])+str(self.fields["TargetNameStr"])+str(self.fields["Av1"])+str(self.fields["Av1Len"])+str(self.fields["Av1Str"])+str(self.fields["Av2"])+str(self.fields["Av2Len"])+str(self.fields["Av2Str"])+str(self.fields["Av3"])+str(self.fields["Av3Len"])+str(self.fields["Av3Str"])+str(self.fields["Av4"])+str(self.fields["Av4Len"])+str(self.fields["Av4Str"])+str(self.fields["Av5"])+str(self.fields["Av5Len"])+str(self.fields["Av5Str"])+str(self.fields["Av6"])+str(self.fields["Av6Len"])

        CalculateSSPI = str(self.fields["Signature"])+str(self.fields["SignatureNull"])+str(self.fields["MessageType"])+str(self.fields["TargetNameLen"])+str(self.fields["TargetNameMaxLen"])+str(self.fields["TargetNameOffset"])+str(self.fields["NegoFlags"])+str(self.fields["ServerChallenge"])+str(self.fields["Reserved"])+str(self.fields["TargetInfoLen"])+str(self.fields["TargetInfoMaxLen"])+str(self.fields["TargetInfoOffset"])+str(self.fields["NTLMOsVersion"])+str(self.fields["TargetNameStr"])+str(self.fields["Av1"])+str(self.fields["Av1Len"])+str(self.fields["Av1Str"])+str(self.fields["Av2"])+str(self.fields["Av2Len"])+str(self.fields["Av2Str"])+str(self.fields["Av3"])+str(self.fields["Av3Len"])+str(self.fields["Av3Str"])+str(self.fields["Av4"])+str(self.fields["Av4Len"])+str(self.fields["Av4Str"])+str(self.fields["Av5"])+str(self.fields["Av5Len"])+str(self.fields["Av5Str"])+str(self.fields["Av6"])+str(self.fields["Av6Len"])

        CalculateNameOffset = str(self.fields["Signature"])+str(self.fields["SignatureNull"])+str(self.fields["MessageType"])+str(self.fields["TargetNameLen"])+str(self.fields["TargetNameMaxLen"])+str(self.fields["TargetNameOffset"])+str(self.fields["NegoFlags"])+str(self.fields["ServerChallenge"])+str(self.fields["Reserved"])+str(self.fields["TargetInfoLen"])+str(self.fields["TargetInfoMaxLen"])+str(self.fields["TargetInfoOffset"])+str(self.fields["NTLMOsVersion"])

        CalculateAvPairsOffset = CalculateNameOffset+str(self.fields["TargetNameStr"])

        CalculateAvPairsLen = str(self.fields["Av1"])+str(self.fields["Av1Len"])+str(self.fields["Av1Str"])+str(self.fields["Av2"])+str(self.fields["Av2Len"])+str(self.fields["Av2Str"])+str(self.fields["Av3"])+str(self.fields["Av3Len"])+str(self.fields["Av3Str"])+str(self.fields["Av4"])+str(self.fields["Av4Len"])+str(self.fields["Av4Str"])+str(self.fields["Av5"])+str(self.fields["Av5Len"])+str(self.fields["Av5Str"])+str(self.fields["Av6"])+str(self.fields["Av6Len"])

        self.fields["Len"] = struct.pack(">h",len(CalculateCompletePacket))
        self.fields["SSPIBuffLen"] = struct.pack("<i",len(CalculateSSPI))[:2]
        # Target Name Offsets
        self.fields["TargetNameOffset"] = struct.pack("<i", len(CalculateNameOffset))
        self.fields["TargetNameLen"] = struct.pack("<i", len(self.fields["TargetNameStr"]))[:2]
        self.fields["TargetNameMaxLen"] = struct.pack("<i", len(self.fields["TargetNameStr"]))[:2]
        #AvPairs Offsets
        self.fields["TargetInfoOffset"] = struct.pack("<i", len(CalculateAvPairsOffset))
        self.fields["TargetInfoLen"] = struct.pack("<i", len(CalculateAvPairsLen))[:2]
        self.fields["TargetInfoMaxLen"] = struct.pack("<i", len(CalculateAvPairsLen))[:2]
        #AvPairs StrLen
        self.fields["Av1Len"] = struct.pack("<i", len(str(self.fields["Av1Str"])))[:2]
        self.fields["Av2Len"] = struct.pack("<i", len(str(self.fields["Av2Str"])))[:2]
        self.fields["Av3Len"] = struct.pack("<i", len(str(self.fields["Av3Str"])))[:2]
        self.fields["Av4Len"] = struct.pack("<i", len(str(self.fields["Av4Str"])))[:2]
        self.fields["Av5Len"] = struct.pack("<i", len(str(self.fields["Av5Str"])))[:2]
        #AvPairs 6 len is always 00.
