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

#IMAP4 Greating class
class IMAPGreating(Packet):
    fields = OrderedDict([
        ("Code",             "* OK IMAP4 service is ready."),
        ("CRLF",        "\r\n"), 
        ]) 

#IMAP4 Capability class
class IMAPCapability(Packet):
    fields = OrderedDict([
        ("Code",             "* CAPABILITY IMAP4 IMAP4rev1 AUTH=PLAIN"),
        ("CRLF",        "\r\n"), 
        ]) 

#IMAP4 Capability class
class IMAPCapabilityEnd(Packet):
    fields = OrderedDict([
        ("Tag",             ""),
        ("Message",         " OK CAPABILITY completed."),
        ("CRLF",        "\r\n"), 
        ]) 
