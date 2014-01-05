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
import re,socket,struct
from socket import *
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

def longueur(payload):
    length = struct.pack(">i", len(''.join(payload)))
    return length

class SMBHeader(Packet):
    fields = OrderedDict([
        ("proto", "\xff\x53\x4d\x42"),
        ("cmd", "\x72"),
        ("error-code", "\x00\x00\x00\x00" ),
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

class SMBNego(Packet):
    fields = OrderedDict([
        ("wordcount", "\x00"),
        ("bcc", "\x62\x00"),
        ("data", "")
    ])
    
    def calculate(self):
        self.fields["bcc"] = struct.pack("<h",len(str(self.fields["data"])))

class SMBNegoData(Packet):
    fields = OrderedDict([
        ("separator1","\x02" ),
        ("dialect1", "\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00"),
        ("separator2","\x02"),
        ("dialect2", "\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00"),
        ("separator3","\x02"),
        ("dialect3", "\x57\x69\x6e\x64\x6f\x77\x73\x20\x66\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70\x73\x20\x33\x2e\x31\x61\x00"),
        ("separator4","\x02"),
        ("dialect4", "\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\x00"),
        ("separator5","\x02"),
        ("dialect5", "\x4c\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00"),
        ("separator6","\x02"),
        ("dialect6", "\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00"),
    ])

class SMBSessionFingerData(Packet):
    fields = OrderedDict([
        ("wordcount", "\x0c"),
        ("AndXCommand", "\xff"),
        ("reserved","\x00" ),
        ("andxoffset", "\x00\x00"),
        ("maxbuff","\x04\x11"),
        ("maxmpx", "\x32\x00"),
        ("vcnum","\x00\x00"),
        ("sessionkey", "\x00\x00\x00\x00"),
        ("securitybloblength","\x4a\x00"),
        ("reserved2","\x00\x00\x00\x00"),
        ("capabilities", "\xd4\x00\x00\xa0"),
        ("bcc1",""),
        ("Data","\x60\x48\x06\x06\x2b\x06\x01\x05\x05\x02\xa0\x3e\x30\x3c\xa0\x0e\x30\x0c\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a\xa2\x2a\x04\x28\x4e\x54\x4c\x4d\x53\x53\x50\x00\x01\x00\x00\x00\x07\x82\x08\xa2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x01\x28\x0a\x00\x00\x00\x0f\x00\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x32\x00\x30\x00\x30\x00\x32\x00\x20\x00\x53\x00\x65\x00\x72\x00\x76\x00\x69\x00\x63\x00\x65\x00\x20\x00\x50\x00\x61\x00\x63\x00\x6b\x00\x20\x00\x33\x00\x20\x00\x32\x00\x36\x00\x30\x00\x30\x00\x00\x00\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x32\x00\x30\x00\x30\x00\x32\x00\x20\x00\x35\x00\x2e\x00\x31\x00\x00\x00\x00\x00"),

    ])
    def calculate(self): 
        self.fields["bcc1"] = struct.pack("<i", len(str(self.fields["Data"])))[:2]   


def OsNameClientVersion(data):
    lenght = struct.unpack('<H',data[43:45])[0]
    pack = tuple(data[47+lenght:].split('\x00\x00\x00'))[:2]
    var = [e.replace('\x00','') for e in data[47+lenght:].split('\x00\x00\x00')[:2]]
    OsVersion = tuple(var)[0]
    return OsVersion


def RunSmbFinger(host):
    s = socket(AF_INET, SOCK_STREAM)
    s.connect(host)
    s.settimeout(0.7)
    h = SMBHeader(cmd="\x72",flag1="\x18",flag2="\x53\xc8")
    n = SMBNego(data = SMBNegoData())
    n.calculate()
    packet0 = str(h)+str(n)
    buffer0 = longueur(packet0)+packet0
    s.send(buffer0)
    data = s.recv(2048)
    if data[8:10] == "\x72\x00":
       head = SMBHeader(cmd="\x73",flag1="\x18",flag2="\x17\xc8",uid="\x00\x00")
       t = SMBSessionFingerData()
       t.calculate()
       final = t 
       packet0 = str(head)+str(final)
       buffer1 = longueur(packet0)+packet0  
       s.send(buffer1) 
       data = s.recv(2048)
    if data[8:10] == "\x73\x16":
       return OsNameClientVersion(data)
