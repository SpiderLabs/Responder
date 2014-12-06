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
import datetime, struct
import sys,socket,struct
from socket import *
from odict import OrderedDict

class Packet():
    fields = OrderedDict([
        ("", ""),
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

def GetBootTime(data):
    Filetime = int(struct.unpack('<q',data)[0])
    t = divmod(Filetime - 116444736000000000, 10000000)
    time = datetime.datetime.fromtimestamp(t[0])
    return time, time.strftime('%Y-%m-%d %H:%M:%S')


def IsDCVuln(t):
    Date = datetime.datetime(2014, 11, 17, 0, 30)
    if t[0] < Date:
       print "DC is up since:", t[1]
       print "This DC is vulnerable to MS14-068"
    else:
       print "DC is up since:", t[1]

def NbtLen(data):
    Len = struct.pack(">i", len(data))
    return Len

class SMBHeader(Packet):
    fields = OrderedDict([
        ("Proto", "\xff\x53\x4d\x42"),
        ("Cmd", "\x72"),
        ("Error-Code", "\x00\x00\x00\x00" ),
        ("Flag1", "\x10"),
        ("Flag2", "\x00\x00"),
        ("Pidhigh", "\x00\x00"),
        ("Signature", "\x00\x00\x00\x00\x00\x00\x00\x00"),
        ("Reserved", "\x00\x00"),
        ("TID", "\x00\x00"),
        ("PID", "\xff\xfe"),
        ("UID", "\x00\x00"),
        ("MID", "\x00\x00"),
    ])

class SMBNego(Packet):
    fields = OrderedDict([
        ("Wordcount", "\x00"),
        ("Bcc", "\x62\x00"),
        ("Data", "")
    ])
    
    def calculate(self):
        self.fields["Bcc"] = struct.pack("<H",len(str(self.fields["Data"])))

class SMBNegoData(Packet):
    fields = OrderedDict([
        ("StrType","\x02" ),
        ("dialect", "NT LM 0.12\x00"),
        ("StrType1","\x02"),
        ("dialect1", "SMB 2.002\x00"),
        ("StrType2","\x02"),
        ("dialect2", "SMB 2.???\x00"),
    ])

def run(host):
    s = socket(AF_INET, SOCK_STREAM)
    s.connect(host)  
    s.settimeout(5) 
    h = SMBHeader(Cmd="\x72",Flag1="\x18",Flag2="\x53\xc8")
    n = SMBNego(Data = SMBNegoData())
    n.calculate()
    packet0 = str(h)+str(n)
    buffer0 = NbtLen(packet0)+packet0
    s.send(buffer0)
    try:
        data = s.recv(1024)
        if data[4:5] == "\xff":
           print "This host doesn't support SMBv2" 
        if data[4:5] == "\xfe":
           IsDCVuln(GetBootTime(data[116:124]))
    except Exception:
        s.close()
        raise

if __name__ == "__main__":
    if len(sys.argv)<=1:
        sys.exit('Usage: python '+sys.argv[0]+' DC-IP-address')
    host = sys.argv[1],445
    run(host)
