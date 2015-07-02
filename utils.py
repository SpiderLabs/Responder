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
import settings

def color(txt, code = 1, modifier = 0):

	if txt.startswith('[*]'):
		settings.Config.PoisonersLogger.warning(txt)
	
	elif 'Analyze' in txt:
		settings.Config.AnalyzeLogger.warning(txt)

	return "\033[%d;3%dm%s\033[0m" % (modifier, code, txt)

def text(txt):
	logging.info(txt)
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

def Parse_IPV6_Addr(data):

	if data[len(data)-4:len(data)][1] =="\x1c":
		return False

	elif data[len(data)-4:len(data)] == "\x00\x01\x00\x01":
		return True

	elif data[len(data)-4:len(data)] == "\x00\xff\x00\x01":
		return True

	else:
		return False

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
