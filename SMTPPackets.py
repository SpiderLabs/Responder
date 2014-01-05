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

#SMTP Greating class
class SMTPGreating(Packet):
    fields = OrderedDict([
        ("Code",             "220"),
        ("Separator",        "\x20"), 
        ("Message",          "smtp01.local ESMTP"),
        ("CRLF",             "\x0d\x0a"),
        ]) 

class SMTPAUTH(Packet):
    fields = OrderedDict([
        ("Code0",            "250"),
        ("Separator0",       "\x2d"), 
        ("Message0",         "smtp01.local"),
        ("CRLF0",            "\x0d\x0a"),
        ("Code",             "250"),
        ("Separator",        "\x20"), 
        ("Message",          "AUTH LOGIN PLAIN XYMCOOKIE"),
        ("CRLF",             "\x0d\x0a"),
        ]) 

class SMTPAUTH1(Packet):
    fields = OrderedDict([
        ("Code",             "334"),
        ("Separator",        "\x20"), 
        ("Message",          "VXNlcm5hbWU6"),#Username
        ("CRLF",             "\x0d\x0a"),

        ]) 

class SMTPAUTH2(Packet):
    fields = OrderedDict([
        ("Code",             "334"),
        ("Separator",        "\x20"), 
        ("Message",          "UGFzc3dvcmQ6"),#Password
        ("CRLF",             "\x0d\x0a"),

        ]) 


