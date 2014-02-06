import struct
from odict import OrderedDict

def longueur(payload):
    length = struct.pack(">i", len(''.join(payload)))
    return length

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
        ("error-code", "\x00\x00\x00\x00" ),
        ("flag1", "\x08"),
        ("flag2", "\x01\x00"),
        ("pidhigh", "\x00\x00"),
        ("signature", "\x00\x00\x00\x00\x00\x00\x00\x00"),
        ("reserved", "\x00\x00"),
        ("tid", "\x00\x00"),
        ("pid", "\x3c\x1b"),
        ("uid", "\x00\x00"),
        ("mid", "\x00\x00"),
    ])

class SMBNegoData(Packet):
    fields = OrderedDict([
        ("wordcount", "\x00"),
        ("bcc", "\x54\x00"),
        ("separator1","\x02" ),
        ("dialect1", "\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00"),
        ("separator2","\x02"),
        ("dialect2", "\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00"),
    ])
    def calculate(self):
        CalculateBCC = str(self.fields["separator1"])+str(self.fields["dialect1"])+str(self.fields["separator2"])+str(self.fields["dialect2"])
        self.fields["bcc"] = struct.pack("<h",len(CalculateBCC))

class SMBSessionData(Packet):
    fields = OrderedDict([
        ("wordcount", "\x0a"),
        ("AndXCommand", "\xff"),
        ("reserved","\x00"),
        ("andxoffset", "\x00\x00"),
        ("maxbuff","\xff\xff"),
        ("maxmpx", "\x02\x00"),
        ("vcnum","\x01\x00"),
        ("sessionkey", "\x00\x00\x00\x00"),
        ("PasswordLen","\x18\x00"),
        ("reserved2","\x00\x00\x00\x00"),
        ("bcc","\x3b\x00"),
        ("AccountPassword",""),
        ("AccountName",""),
        ("AccountNameTerminator","\x00"),
        ("PrimaryDomain","WORKGROUP"),
        ("PrimaryDomainTerminator","\x00"),
        ("NativeOs","Unix"),
        ("NativeOsTerminator","\x00"),
        ("NativeLanman","Samba"),
        ("NativeLanmanTerminator","\x00"),

    ])
    def calculate(self): 
        CompleteBCC = str(self.fields["AccountPassword"])+str(self.fields["AccountName"])+str(self.fields["AccountNameTerminator"])+str(self.fields["PrimaryDomain"])+str(self.fields["PrimaryDomainTerminator"])+str(self.fields["NativeOs"])+str(self.fields["NativeOsTerminator"])+str(self.fields["NativeLanman"])+str(self.fields["NativeLanmanTerminator"])
        self.fields["bcc"] = struct.pack("<h", len(CompleteBCC))
        self.fields["PasswordLen"] = struct.pack("<h", len(str(self.fields["AccountPassword"])))

class SMBTreeConnectData(Packet):
    fields = OrderedDict([
        ("Wordcount", "\x04"),
        ("AndXCommand", "\xff"),
        ("Reserved","\x00" ),
        ("Andxoffset", "\x00\x00"),
        ("Flags","\x08\x00"),
        ("PasswdLen", "\x01\x00"),
        ("Bcc","\x1b\x00"),
        ("Passwd", "\x00"),
        ("Path",""),
        ("PathTerminator","\x00"),
        ("Service","?????"),
        ("Terminator", "\x00"),

    ])
    def calculate(self): 
        self.fields["PasswdLen"] = struct.pack("<h", len(str(self.fields["Passwd"])))[:2]
        BccComplete = str(self.fields["Passwd"])+str(self.fields["Path"])+str(self.fields["PathTerminator"])+str(self.fields["Service"])+str(self.fields["Terminator"])
        self.fields["Bcc"] = struct.pack("<h", len(BccComplete))

class RAPNetServerEnum3Data(Packet):
    fields = OrderedDict([
        ("Command", "\xd7\x00"),
        ("ParamDescriptor", "WrLehDzz"),
        ("ParamDescriptorTerminator", "\x00"),
        ("ReturnDescriptor","B16BBDz"),
        ("ReturnDescriptorTerminator", "\x00"),
        ("DetailLevel", "\x01\x00"),
        ("RecvBuff","\xff\xff"),
        ("ServerType", "\x00\x00\x00\x80"),
        ("TargetDomain","SMB"),
        ("RapTerminator","\x00"),
        ("TargetName","ABCD"),
        ("RapTerminator2","\x00"),
    ])

class SMBTransRAPData(Packet):
    fields = OrderedDict([
        ("Wordcount", "\x0e"),
        ("TotalParamCount", "\x24\x00"),
        ("TotalDataCount","\x00\x00" ),
        ("MaxParamCount", "\x08\x00"),
        ("MaxDataCount","\xff\xff"),
        ("MaxSetupCount", "\x00"),
        ("Reserved","\x00\x00"),
        ("Flags", "\x00"),
        ("Timeout","\x00\x00\x00\x00"),
        ("Reserved1","\x00\x00"),
        ("ParamCount","\x24\x00"),
        ("ParamOffset", "\x5a\x00"),
        ("DataCount", "\x00\x00"),
        ("DataOffset", "\x7e\x00"),
        ("SetupCount", "\x00"),
        ("Reserved2", "\x00"),
        ("Bcc", "\x3f\x00"),
        ("Terminator", "\x00"),
        ("PipeName", "\\PIPE\\LANMAN"),
        ("PipeTerminator","\x00\x00"),
        ("Data", ""),

    ])
    def calculate(self):
        #Padding
        if len(str(self.fields["Data"]))%2==0:
           self.fields["PipeTerminator"] = "\x00\x00\x00\x00"
        else:
           self.fields["PipeTerminator"] = "\x00\x00\x00"
        ##Convert Path to Unicode first before any Len calc.
        self.fields["PipeName"] = self.fields["PipeName"].encode('utf-16le')
        ##Data Len
        self.fields["TotalParamCount"] = struct.pack("<i", len(str(self.fields["Data"])))[:2]
        self.fields["ParamCount"] = struct.pack("<i", len(str(self.fields["Data"])))[:2]
        ##Packet len
        FindRAPOffset = str(self.fields["Wordcount"])+str(self.fields["TotalParamCount"])+str(self.fields["TotalDataCount"])+str(self.fields["MaxParamCount"])+str(self.fields["MaxDataCount"])+str(self.fields["MaxSetupCount"])+str(self.fields["Reserved"])+str(self.fields["Flags"])+str(self.fields["Timeout"])+str(self.fields["Reserved1"])+str(self.fields["ParamCount"])+str(self.fields["ParamOffset"])+str(self.fields["DataCount"])+str(self.fields["DataOffset"])+str(self.fields["SetupCount"])+str(self.fields["Reserved2"])+str(self.fields["Bcc"])+str(self.fields["Terminator"])+str(self.fields["PipeName"])+str(self.fields["PipeTerminator"])

        self.fields["ParamOffset"] = struct.pack("<i", len(FindRAPOffset)+32)[:2]
        ##Bcc Buff Len
        BccComplete    = str(self.fields["Terminator"])+str(self.fields["PipeName"])+str(self.fields["PipeTerminator"])+str(self.fields["Data"])
        self.fields["Bcc"] = struct.pack("<i", len(BccComplete))[:2]
