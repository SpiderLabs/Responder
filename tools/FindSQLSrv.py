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
from socket import *

print 'MSSQL Server Finder 0.1'

s = socket(AF_INET,SOCK_DGRAM)
s.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
s.settimeout(2)
s.sendto('\x02',('255.255.255.255',1434))

try:
   while 1:
      data, address = s.recvfrom(8092)
      if not data:
         break
      else:
         print "==============================================================="
         print "Host details:",address[0]
         print data[2:]
         print "==============================================================="
         print ""
except:
   pass


