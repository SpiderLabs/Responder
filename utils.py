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
import sys
import re
import logging
import socket
import time
import settings

try:
	import sqlite3
except:
	print "[!] Please install python-sqlite3 extension."
	sys.exit(0)

def color(txt, code = 1, modifier = 0):

	if txt.startswith('[*]'):
		settings.Config.PoisonersLogger.warning(txt)
	
	elif 'Analyze' in txt:
		settings.Config.AnalyzeLogger.warning(txt)

	# No colors for windows...
	if os.name == 'nt':
		return txt

	return "\033[%d;3%dm%s\033[0m" % (modifier, code, txt)

def text(txt):
	logging.info(txt)

	if os.name == 'nt':
		return txt

	return '\r'+re.sub(r'\[([^]]*)\]', "\033[1;34m[\\1]\033[0m", txt)

def RespondToThisIP(ClientIp):

	if ClientIp.startswith('127.0.0.'):
		return False

	if len(settings.Config.RespondTo) and ClientIp not in settings.Config.RespondTo:
		return False

	if ClientIp in settings.Config.RespondTo or settings.Config.RespondTo == []:
		if ClientIp not in settings.Config.DontRespondTo:
			return True

	return False

def RespondToThisName(Name):

	if len(settings.Config.RespondToName) and Name.upper() not in settings.Config.RespondToName:
		return False

	if Name.upper() in settings.Config.RespondToName or settings.Config.RespondToName == []:
		if Name.upper() not in settings.Config.DontRespondToName:
			return True

	return False

def RespondToThisHost(ClientIp, Name):
	return (RespondToThisIP(ClientIp) and RespondToThisName(Name))

def IsOsX():
	return True if settings.Config.Os_version == "darwin" else False

def OsInterfaceIsSupported():
	if settings.Config.Interface != "Not set":
		return False if IsOsX() else True
	else:
		return False

def FindLocalIP(Iface):

	if Iface == 'ALL':
		return '0.0.0.0'

	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		s.setsockopt(socket.SOL_SOCKET, 25, Iface+'\0')
		s.connect(("127.0.0.1",9))#RFC 863
		ret = s.getsockname()[0]
		s.close()

		return ret

	except socket.error:
		print color("[!] Error: %s: Interface not found" % Iface, 1)
		sys.exit(-1)

# Function used to write captured hashs to a file.
def WriteData(outfile, data, user):

	logging.info("[*] Captured Hash: %s" % data)

	if os.path.isfile(outfile) == False:
		with open(outfile,"w") as outf:
			outf.write(data)
			outf.write("\n")
			outf.close()

	else:
		with open(outfile,"r") as filestr:
			if re.search(user.encode('hex'), filestr.read().encode('hex')):
				filestr.close()
				return False
			if re.search(re.escape("$"), user):
				filestr.close()
				return False

		with open(outfile,"a") as outf2:
			outf2.write(data)
			outf2.write("\n")
			outf2.close()

def SaveToDb(result):

	# Creating the DB if it doesn't exist
	if not os.path.exists(settings.Config.DatabaseFile):
		cursor = sqlite3.connect(settings.Config.DatabaseFile)
		cursor.execute('CREATE TABLE responder (timestamp varchar(32), module varchar(16), type varchar(16), client varchar(32), hostname varchar(32), user varchar(32), cleartext varchar(128), hash varchar(512), fullhash varchar(512))')
		cursor.commit()
		cursor.close()

	for k in [ 'module', 'type', 'client', 'hostname', 'user', 'cleartext', 'hash', 'fullhash' ]:
		if not k in result:
			result[k] = ''

	if len(result['user']) < 2:
		return

	if len(result['cleartext']):
		fname = '%s-%s-ClearText-%s.txt' % (result['module'], result['type'], result['client'])
	else:
		fname = '%s-%s-%s.txt' % (result['module'], result['type'], result['client'])
	
	timestamp = time.strftime("%d-%m-%Y %H:%M:%S")
	logfile = os.path.join(settings.Config.ResponderPATH, 'logs', fname)

	cursor = sqlite3.connect(settings.Config.DatabaseFile)
	res = cursor.execute("SELECT COUNT(*) AS count FROM responder WHERE module=? AND type=? AND LOWER(user)=LOWER(?)", (result['module'], result['type'], result['user']))
	(count,) = res.fetchone()

	if count == 0:
		
		# Write JtR-style hash string to file
		with open(logfile,"a") as outf:
			outf.write(result['fullhash'])
			outf.write("\n")
			outf.close()

		# Update database
		cursor.execute("INSERT INTO responder VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)", (timestamp, result['module'], result['type'], result['client'], result['hostname'], result['user'], result['cleartext'], result['hash'], result['fullhash']))
		cursor.commit()

	cursor.close()

	# Print output
	if count == 0 or settings.Config.Verbose:

		if len(result['client']):
			print text("[%s] %s Client   : %s" % (result['module'], result['type'], color(result['client'], 3)))
		if len(result['hostname']):
			print text("[%s] %s Hostname : %s" % (result['module'], result['type'], color(result['hostname'], 3)))
		if len(result['user']):
			print text("[%s] %s Username : %s" % (result['module'], result['type'], color(result['user'], 3)))
		
		# Bu order of priority, print cleartext, fullhash, or hash
		if len(result['cleartext']):
			print text("[%s] %s Password : %s" % (result['module'], result['type'], color(result['cleartext'], 3)))
		elif len(result['fullhash']):
			print text("[%s] %s Hash     : %s" % (result['module'], result['type'], color(result['fullhash'], 3)))
		elif len(result['hash']):
			print text("[%s] %s Hash     : %s" % (result['module'], result['type'], color(result['hash'], 3)))
			
	else:
		print color('[*]', 2, 1), 'Skipping previously captured hash for %s' % result['user']


def Parse_IPV6_Addr(data):

	if data[len(data)-4:len(data)][1] =="\x1c":
		return False

	elif data[len(data)-4:len(data)] == "\x00\x01\x00\x01":
		return True

	elif data[len(data)-4:len(data)] == "\x00\xff\x00\x01":
		return True

	else:
		return False

def Decode_Name(nbname):
	#From http://code.google.com/p/dpkt/ with author's permission.
	try:
		from string import printable

		if len(nbname) != 32:
			return nbname
		
		l = []
		for i in range(0, 32, 2):
			l.append(chr(((ord(nbname[i]) - 0x41) << 4) | ((ord(nbname[i+1]) - 0x41) & 0xf)))
		
		return filter(lambda x: x in printable, ''.join(l).split('\x00', 1)[0].replace(' ', ''))
	
	except:
		return "Illegal NetBIOS name"

def NBT_NS_Role(data):
	Role = {
		"\x41\x41\x00":"Workstation/Redirector",
		"\x42\x4c\x00":"Domain Master Browser",
		"\x42\x4d\x00":"Domain Controller",
		"\x42\x4e\x00":"Local Master Browser",
		"\x42\x4f\x00":"Browser Election",
		"\x43\x41\x00":"File Server",
		"\x41\x42\x00":"Browser",
	}

	return Role[data] if data in Role else "Service not known"

def banner():

	banner = "\n".join([
		'                                         __',
		'  .----.-----.-----.-----.-----.-----.--|  |.-----.----.',
		'  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|',
		'  |__| |_____|_____|   __|_____|__|__|_____||_____|__|',
		'                   |__|'
	])

	print banner
	print "\n           \033[1;33mNBT-NS, LLMNR & MDNS %s\033[0m" % settings.__version__
	print ""
	print "  Original work by Laurent Gaffie (lgaffie@trustwave.com)"
	print "  To kill this script hit CRTL-C"
	print ""

def StartupMessage():
	enabled  = color('[ON]', 2, 1) 
	disabled = color('[OFF]', 1, 1)

	print ""
	print color("[+] ", 2, 1) + "Poisoners:"
	print '    %-27s' % "LLMNR" + enabled
	print '    %-27s' % "NBT-NS" + enabled
	print '    %-27s' % "DNS/MDNS" + enabled
	print ""

	print color("[+] ", 2, 1) + "Servers:"
	print '    %-27s' % "HTTP server" + (enabled if settings.Config.HTTP_On_Off else disabled)
	print '    %-27s' % "HTTPS server" + (enabled if settings.Config.SSL_On_Off else disabled)
	print '    %-27s' % "WPAD proxy" + (enabled if settings.Config.WPAD_On_Off else disabled)
	print '    %-27s' % "SMB server" + (enabled if settings.Config.SMB_On_Off else disabled)
	print '    %-27s' % "Kerberos server" + (enabled if settings.Config.Krb_On_Off else disabled)
	print '    %-27s' % "SQL server" + (enabled if settings.Config.SQL_On_Off else disabled)
	print '    %-27s' % "FTP server" + (enabled if settings.Config.FTP_On_Off else disabled)
	print '    %-27s' % "IMAP server" + (enabled if settings.Config.IMAP_On_Off else disabled)
	print '    %-27s' % "POP3 server" + (enabled if settings.Config.POP_On_Off else disabled)
	print '    %-27s' % "SMTP server" + (enabled if settings.Config.SMTP_On_Off else disabled)
	print '    %-27s' % "DNS server" + (enabled if settings.Config.DNS_On_Off else disabled)
	print '    %-27s' % "LDAP server" + (enabled if settings.Config.LDAP_On_Off else disabled)
	print ""

	print color("[+] ", 2, 1) + "HTTP Options:"
	print '    %-27s' % "Always serving EXE" + (enabled if settings.Config.Serve_Always else disabled)
	print '    %-27s' % "Serving EXE" + (enabled if settings.Config.Serve_Exe else disabled)
	print '    %-27s' % "Serving HTML" + (enabled if settings.Config.Serve_Html else disabled)
	print '    %-27s' % "Upstream Proxy" + (enabled if settings.Config.Upstream_Proxy else disabled)
	#print '    %-27s' % "WPAD script" + settings.Config.WPAD_Script
	print ""

	print color("[+] ", 2, 1) + "Poisoning Options:"
	print '    %-27s' % "Analyze Mode" + (enabled if settings.Config.AnalyzeMode else disabled)
	print '    %-27s' % "Force WPAD auth" + (enabled if settings.Config.Force_WPAD_Auth else disabled)
	print '    %-27s' % "Force Basic Auth" + (enabled if settings.Config.Basic else disabled)
	print '    %-27s' % "Force LM downgrade" + (enabled if settings.Config.LM_On_Off == True else disabled)
	print '    %-27s' % "Fingerprint hosts" + (enabled if settings.Config.Finger_On_Off == True else disabled)
	print ""

	print color("[+] ", 2, 1) + "Generic Options:"
	print '    %-27s' % "Responder NIC" + color('[%s]' % settings.Config.Interface, 5, 1)
	print '    %-27s' % "Responder IP" + color('[%s]' % settings.Config.Bind_To, 5, 1)
	print '    %-27s' % "Challenge set" + color('[%s]' % settings.Config.NumChal, 5, 1)

	if settings.Config.Upstream_Proxy:
		print '    %-27s' % "Upstream Proxy" + color('[%s]' % settings.Config.Upstream_Proxy, 5, 1)

	if len(settings.Config.RespondTo):
		print '    %-27s' % "Respond To" + color(str(settings.Config.RespondTo), 5, 1)

	if len(settings.Config.RespondToName):
		print '    %-27s' % "Respond To Names" + color(str(settings.Config.RespondToName), 5, 1)

	if len(settings.Config.DontRespondTo):
		print '    %-27s' % "Don't Respond To" + color(str(settings.Config.DontRespondTo), 5, 1)

	if len(settings.Config.DontRespondToName):
		print '    %-27s' % "Don't Respond To Names" + color(str(settings.Config.DontRespondToName), 5, 1)

	print ""
	print ""

# Useful for debugging
def hexdump(src, l=0x16):
	res = []
	sep = '.'
	src = str(src)

	for i in range(0, len(src), l):
		s = src[i:i+l]
		hexa = ''

		for h in range(0,len(s)):
			if h == l/2:
				hexa += ' '
			h = s[h]
			if not isinstance(h, int):
				h = ord(h)
			h = hex(h).replace('0x','')
			if len(h) == 1:
				h = '0'+h
			hexa += h + ' '

		hexa = hexa.strip(' ')
		text = ''

		for c in s:
			if not isinstance(c, int):
				c = ord(c)

			if 0x20 <= c < 0x7F:
				text += chr(c)
			else:
				text += sep

		res.append(('%08X:  %-'+str(l*(2+1)+1)+'s  |%s|') % (i, hexa, text))

	return '\n'.join(res)
