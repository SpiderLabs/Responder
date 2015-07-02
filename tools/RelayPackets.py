#!/usr/bin/env python
# This file is part of Responder
# Original work by Laurent Gaffie - Trustwave Holdings
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

class SMBHeader(Packet):
    fields = OrderedDict([
        ("proto", "\xff\x53\x4d\x42"),
        ("cmd", "\x72"),
        ("errorcode", "\x00\x00\x00\x00"),
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
        ("Wordcount", "\x00"),
        ("Bcc", "\x62\x00"),
        ("Data", "")
    ])
    
    def calculate(self):
        self.fields["Bcc"] = struct.pack("<h",len(str(self.fields["Data"])))

class SMBNegoData(Packet):
    fields = OrderedDict([
        ("Separator1","\x02" ),
        ("Dialect1", "\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00"),
        ("Separator2","\x02"),
        ("Dialect2", "\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00"),
        ("Separator3","\x02"),
        ("Dialect3", "\x57\x69\x6e\x64\x6f\x77\x73\x20\x66\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70\x73\x20\x33\x2e\x31\x61\x00"),
        ("Separator4","\x02"),
        ("Dialect4", "\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\x00"),
        ("Separator5","\x02"),
        ("Dialect5", "\x4c\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00"),
        ("Separator6","\x02"),
        ("Dialect6", "\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00"),
    ])

class SMBSessionTreeData(Packet):
    fields = OrderedDict([
        ("Wordcount",   "\x0d"),
        ("AndXCommand", "\x75"),
        ("Reserved",    "\x00" ),
        ("Andxoffset", "\x7c\x00"),
        ("Maxbuff","\x04\x11"),
        ("Maxmpx", "\x32\x00"),
        ("Vcnum","\x00\x00"),
        ("Sessionkey", "\x00\x00\x00\x00"),
        ("AnsiPassLength","\x18\x00"),
        ("UnicodePassLength", "\x00\x00"),
        ("Reserved2","\x00\x00\x00\x00"),
        ("Capabilities", "\xd4\x00\x00\x00"),
        ("Bcc","\x3f\x00"),   
        ("AnsiPasswd", "\xe3\xa7\x10\x56\x58\xed\x92\xa1\xea\x9d\x55\xb1\x63\x99\x7f\xbe\x1c\xbd\x6c\x0a\xf8\xef\xb2\x89"),
        ("UnicodePasswd", "\xe3\xa7\x10\x56\x58\xed\x92\xa1\xea\x9d\x55\xb1\x63\x99\x7f\xbe\x1c\xbd\x6c\x0a\xf8\xef\xb2\x89"),
        ("Username","Administrator"),
        ("UsernameTerminator","\x00\x00"),
        ("Domain","SMB"),
        ("DomainTerminator","\x00\x00"),
        ("Nativeos",""),
        ("NativeosTerminator","\x00\x00"),
        ("Lanmanager",""),
        ("LanmanagerTerminator","\x00\x00\x00"),
        ("Wordcount2","\x04"),
        ("Andxcmd2","\xff"),
        ("Reserved3","\x00"),
        ("Andxoffset2","\x06\x01"),
        ("Flags","\x08\x00"),
        ("PasswordLength","\x01\x00"),
        ("Bcc2","\x19\x00"),
        ("Passwd","\x00"),
        ("PrePath","\\\\"),
        ("Targ", "CSCDSFCS"),
        ("IPC", "\\IPC$"),
        ("TerminatorPath","\x00\x00"),
        ("Service","?????"),
        ("TerminatorService","\x00"),
    ])
    def calculate(self):
        ##Convert first
        self.fields["Username"] = self.fields["Username"].encode('utf-16be')
        self.fields["Domain"] = self.fields["Domain"].encode('utf-16be')
        self.fields["Nativeos"] = self.fields["Nativeos"].encode('utf-16be')
        self.fields["Lanmanager"] = self.fields["Lanmanager"].encode('utf-16be')
        self.fields["PrePath"] = self.fields["PrePath"].encode('utf-16le')
        self.fields["Targ"] = self.fields["Targ"].encode('utf-16le')
        self.fields["IPC"] = self.fields["IPC"].encode('utf-16le')
        ##Then calculate
        data1= str(self.fields["AnsiPasswd"])+(self.fields["UnicodePasswd"])+str(self.fields["Username"])+str(self.fields["UsernameTerminator"])+str(self.fields["Domain"])+str(self.fields["DomainTerminator"])+str(self.fields["Nativeos"])+str(self.fields["NativeosTerminator"])+str(self.fields["Lanmanager"])+str(self.fields["LanmanagerTerminator"])

        data2= str(self.fields["Passwd"])+str(self.fields["PrePath"])+str(self.fields["Targ"])+str(self.fields["IPC"])+str(self.fields["TerminatorPath"])+str(self.fields["Service"])+str(self.fields["TerminatorService"])

        self.fields["Bcc"] = struct.pack("<h",len(data1))
        self.fields["Bcc2"] = struct.pack("<h",len(data2))
        self.fields["Andxoffset"] = struct.pack("<h",len(data1)+32+29)
        self.fields["AnsiPassLength"] = struct.pack("<h",len(str(self.fields["AnsiPasswd"])))
        self.fields["UnicodePassLength"] = struct.pack("<h",len(str(self.fields["UnicodePasswd"])))
        self.fields["PasswordLength"] = struct.pack("<h",len(str(self.fields["Passwd"])))

class SMBNTCreateData(Packet):
    fields = OrderedDict([
        ("Wordcount",     "\x18"),
        ("AndXCommand",   "\xff"),
        ("Reserved",      "\x00" ),
        ("Andxoffset",    "\x00\x00"),
        ("Reserved2",     "\x00"),
        ("FileNameLen",   "\x07\x00"),
        ("CreateFlags",   "\x16\x00\x00\x00"),
        ("RootFID",       "\x00\x00\x00\x00"),
        ("AccessMask",    "\x00\x00\x00\x02"),
        ("AllocSize",     "\x00\x00\x00\x00\x00\x00\x00\x00"),
        ("FileAttrib",    "\x00\x00\x00\x00"),
        ("ShareAccess",   "\x07\x00\x00\x00"),
        ("Disposition",   "\x01\x00\x00\x00"),   
        ("CreateOptions", "\x00\x00\x00\x00"),
        ("Impersonation", "\x02\x00\x00\x00"),
        ("SecurityFlags", "\x00"),
        ("Bcc",           "\x08\x00"),
        ("FileName",      "\\svcctl"),
        ("FileNameNull",  "\x00"),
    ])

    def calculate(self):

        Data1= str(self.fields["FileName"])+str(self.fields["FileNameNull"])
        self.fields["FileNameLen"] = struct.pack("<h",len(str(self.fields["FileName"])))
        self.fields["Bcc"] = struct.pack("<h",len(Data1))

class SMBReadData(Packet):
    fields = OrderedDict([
        ("Wordcount",     "\x0a"),
        ("AndXCommand",   "\xff"),
        ("Reserved",      "\x00" ),
        ("Andxoffset",    "\x00\x00"),
        ("FID",           "\x00\x00"),
        ("Offset",        "\x19\x03\x00\x00"), 
        ("MaxCountLow",   "\xed\x01"),
        ("MinCount",      "\xed\x01"),
        ("Hidden",        "\xff\xff\xff\xff"),
        ("Remaining",     "\x00\x00"),  
        ("Bcc",           "\x00\x00"),
        ("Data", ""),
    ])

    def calculate(self):

        self.fields["Bcc"] = struct.pack("<h",len(str(self.fields["Data"])))

class SMBWriteData(Packet):
    fields = OrderedDict([
        ("Wordcount",     "\x0e"),
        ("AndXCommand",   "\xff"),
        ("Reserved",      "\x00" ),
        ("Andxoffset",    "\x00\x00"),
        ("FID",           "\x06\x40"),
        ("Offset",        "\xea\x03\x00\x00"),
        ("Reserved2",     "\xff\xff\xff\xff"),
        ("WriteMode",     "\x08\x00"),
        ("Remaining",     "\xdc\x02"),
        ("DataLenHi",     "\x00\x00"),
        ("DataLenLow",    "\xdc\x02"),
        ("DataOffset",    "\x3f\x00"),
        ("HiOffset",      "\x00\x00\x00\x00"),   
        ("Bcc",           "\xdc\x02"),
        ("Data", ""),
    ])

    def calculate(self):
        self.fields["Remaining"] = struct.pack("<h",len(str(self.fields["Data"])))
        self.fields["DataLenLow"] = struct.pack("<h",len(str(self.fields["Data"])))
        self.fields["Bcc"] = struct.pack("<h",len(str(self.fields["Data"])))

class SMBDCEData(Packet):
    fields = OrderedDict([
        ("Version",       "\x05"),
        ("VersionLow",    "\x00"),
        ("PacketType",    "\x0b"),
        ("PacketFlag",    "\x03"),
        ("DataRepresent", "\x10\x00\x00\x00"),
        ("FragLen",       "\x2c\x02"),
        ("AuthLen",       "\x00\x00"),
        ("CallID",        "\x00\x00\x00\x00"),
        ("MaxTransFrag",  "\xd0\x16"),
        ("MaxRecvFrag",   "\xd0\x16"),
        ("GroupAssoc",    "\x00\x00\x00\x00"),
        ("CTXNumber",     "\x01"),
        ("CTXPadding",    "\x00\x00\x00"),
        ("CTX0ContextID",  "\x00\x00"),
        ("CTX0ItemNumber", "\x01\x00"),
        ("CTX0UID", "\x81\xbb\x7a\x36\x44\x98\xf1\x35\xad\x32\x98\xf0\x38\x00\x10\x03"),
        ("CTX0UIDVersion", "\x02\x00"),
        ("CTX0UIDVersionlo","\x00\x00"),
        ("CTX0UIDSyntax",   "\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60"),
        ("CTX0UIDSyntaxVer","\x02\x00\x00\x00"),
    ])

    def calculate(self):

        Data1= str(self.fields["Version"])+str(self.fields["VersionLow"])+str(self.fields["PacketType"])+str(self.fields["PacketFlag"])+str(self.fields["DataRepresent"])+str(self.fields["FragLen"])+str(self.fields["AuthLen"])+str(self.fields["CallID"])+str(self.fields["MaxTransFrag"])+str(self.fields["MaxRecvFrag"])+str(self.fields["GroupAssoc"])+str(self.fields["CTXNumber"])+str(self.fields["CTXPadding"])+str(self.fields["CTX0ContextID"])+str(self.fields["CTX0ItemNumber"])+str(self.fields["CTX0UID"])+str(self.fields["CTX0UIDVersion"])+str(self.fields["CTX0UIDVersionlo"])+str(self.fields["CTX0UIDSyntax"])+str(self.fields["CTX0UIDSyntaxVer"])


        self.fields["FragLen"] = struct.pack("<h",len(Data1))

class SMBDCEPacketData(Packet):
    fields = OrderedDict([
        ("Version",       "\x05"),
        ("VersionLow",    "\x00"),
        ("PacketType",    "\x00"),
        ("PacketFlag",    "\x03"),
        ("DataRepresent", "\x10\x00\x00\x00"),
        ("FragLen",       "\x2c\x02"),
        ("AuthLen",       "\x00\x00"),
        ("CallID",        "\x00\x00\x00\x00"),
        ("AllocHint",     "\x38\x00\x00\x00"),
        ("ContextID",     "\x00\x00"),
        ("Opnum",         "\x0f\x00"),
        ("Data",          ""),

    ])

    def calculate(self):

        Data1= str(self.fields["Version"])+str(self.fields["VersionLow"])+str(self.fields["PacketType"])+str(self.fields["PacketFlag"])+str(self.fields["DataRepresent"])+str(self.fields["FragLen"])+str(self.fields["AuthLen"])+str(self.fields["CallID"])+str(self.fields["AllocHint"])+str(self.fields["ContextID"])+str(self.fields["Opnum"])+str(self.fields["Data"])

        self.fields["FragLen"] = struct.pack("<h",len(Data1))
        self.fields["AllocHint"] = struct.pack("<i",len(str(self.fields["Data"])))

class SMBDCESVCCTLOpenManagerW(Packet):
    fields = OrderedDict([
        ("MachineNameRefID",     "\xb5\x97\xb9\xbc"),
        ("MaxCount",             "\x0f\x00\x00\x00"),
        ("Offset",               "\x00\x00\x00\x00"),
        ("ActualCount",          "\x0f\x00\x00\x00"),
        ("MachineName",          "\\\\169.220.1.11"),##This is not taken into consideration.
        ("MachineNameNull",      "\x00\x00\x00\x00"),
        ("DbPointer",            "\x00\x00\x00\x00"),
        ("AccessMask",           "\x3f\x00\x0f\x00"),
    ])

    def calculate(self):
        ## Convert to UTF-16LE
        self.fields["MachineName"] = self.fields["MachineName"].encode('utf-16le')

class SMBDCESVCCTLCreateService(Packet):
    fields = OrderedDict([
        ("ContextHandle",        ""),
        ("MaxCount",             "\x0c\x00\x00\x00"),
        ("Offset",               "\x00\x00\x00\x00"),
        ("ActualCount",          "\x0c\x00\x00\x00"),
        ("ServiceName",          "AyAGaxwLhCP"),
        ("MachineNameNull",      "\x00\x00"),
        ("ReferentID",           "\x9c\xfa\x9a\xc9"),
        ("MaxCountRefID",        "\x11\x00\x00\x00"),
        ("OffsetID",             "\x00\x00\x00\x00"),
        ("ActualCountRefID",     "\x11\x00\x00\x00"),
        ("DisplayNameID",        "DhhUFcsvrfJvLwRq"),
        ("DisplayNameIDNull",    "\x00\x00\x00\x00"),
        ("AccessMask",           "\xff\x01\x0f\x00"),
        ("ServerType",           "\x10\x01\x00\x00"),
        ("ServiceStartType",     "\x03\x00\x00\x00"),
        ("ServiceErrorCtl",      "\x00\x00\x00\x00"),
        ("BinPathMaxCount",      "\xb6\x00\x00\x00"),
        ("BinPathOffset",        "\x00\x00\x00\x00"),
        ("BinPathActualCount",   "\xb6\x00\x00\x00"),
        ("BinPathName",          "%COMSPEC% /C \""),
        ("BinCMD",               ""),
        ("BintoEnd",             "\""),
        ("BinPathNameNull",      "\x00\x00"),
        ("Nullz",                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
    ])

    def calculate(self):

        BinDataLen = str(self.fields["BinPathName"])+str(self.fields["BinCMD"])+str(self.fields["BintoEnd"])

        ## Calculate first
        self.fields["BinPathMaxCount"] = struct.pack("<i",len(BinDataLen)+1)
        self.fields["BinPathActualCount"] = struct.pack("<i",len(BinDataLen)+1)
        self.fields["MaxCount"] = struct.pack("<i",len(str(self.fields["ServiceName"]))+1)
        self.fields["ActualCount"] = struct.pack("<i",len(str(self.fields["ServiceName"]))+1)
        self.fields["MaxCountRefID"] = struct.pack("<i",len(str(self.fields["DisplayNameID"]))+1)
        self.fields["ActualCountRefID"] = struct.pack("<i",len(str(self.fields["DisplayNameID"]))+1)
        ## Then convert to UTF-16LE, yeah it's weird..
        self.fields["ServiceName"] = self.fields["ServiceName"].encode('utf-16le')
        self.fields["DisplayNameID"] = self.fields["DisplayNameID"].encode('utf-16le')
        self.fields["BinPathName"] = self.fields["BinPathName"].encode('utf-16le')
        self.fields["BinCMD"] = self.fields["BinCMD"].encode('utf-16le')
        self.fields["BintoEnd"] = self.fields["BintoEnd"].encode('utf-16le')

class SMBDCESVCCTLOpenService(Packet):
    fields = OrderedDict([
        ("ContextHandle",        ""),
        ("MaxCount",             "\x0c\x00\x00\x00"),
        ("Offset",               "\x00\x00\x00\x00"),
        ("ActualCount",          "\x0c\x00\x00\x00"),
        ("ServiceName",          ""),
        ("MachineNameNull",      "\x00\x00"),
        ("AccessMask",           "\xff\x01\x0f\x00"),
    ])

    def calculate(self):
        ## Calculate first
        self.fields["MaxCount"] = struct.pack("<i",len(str(self.fields["ServiceName"]))+1)
        self.fields["ActualCount"] = struct.pack("<i",len(str(self.fields["ServiceName"]))+1)
        ## Then convert to UTF-16LE, yeah it's weird..
        self.fields["ServiceName"] = self.fields["ServiceName"].encode('utf-16le')

class SMBDCESVCCTLStartService(Packet):
    fields = OrderedDict([
        ("ContextHandle",        ""),
        ("MaxCount",             "\x00\x00\x00\x00\x00\x00\x00\x00"),
    ])

def ParseAnswerKey(data,host):
    key = data[73:81]
    print "Key retrieved is:%s from host:%s"%(key.encode("hex"),host)
    return key