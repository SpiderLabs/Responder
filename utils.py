#! /usr/bin/env python
import os
import re
import socket
import settings

def color(txt, code = 1, modifier = 0):
	return "\033[%d;3%dm%s\033[0m" % (modifier, code, txt)

def text(txt):
	return re.sub(r'\[([^]]*)\]', "\033[1;34m[\\1]\033[0m", txt)

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
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.setsockopt(socket.SOL_SOCKET, 25, Iface+'\0')
	s.connect(("127.0.0.1",9))#RFC 863
	ret = s.getsockname()[0]
	s.close()
	return ret

# Function used to write captured hashs to a file.
def WriteData(outfile,data, user):
	if os.path.isfile(outfile) == False:
		with open(outfile,"w") as outf:
			outf.write(data)
			outf.write("\n")
			outf.close()

	if os.path.isfile(outfile) == True:
		with open(outfile,"r") as filestr:
			if re.search(user.encode('hex'), filestr.read().encode('hex')):
				filestr.close()
				return False
			if re.search(re.escape("$"), user):
				filestr.close()
				return False
			else:
				with open(outfile,"a") as outf2:
					outf2.write(data)
					outf2.write("\n")
					outf2.close()

def PrintData(outfile, user):

	### TEMP
	return True

	if settings.Config.Verbose == True:
		return True

	if os.path.isfile(outfile) == True:
		with open(outfile,"r") as filestr:
			if re.search(user.encode('hex'), filestr.read().encode('hex')):
				filestr.close()
				return False
			if re.search(re.escape("$"), user):
				filestr.close()
				return False
			else:
				return True
	else:
		return True

def PrintLLMNRNBTNS(outfile, Message):
	if settings.Config.Verbose == True:
		return True

	if os.path.isfile(outfile) == True:
		with open(outfile,"r") as filestr:
			if re.search(re.escape(Message), filestr.read()):
				filestr.close()
				return False
			else:
				return True
	else:
		return True

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
	print "\n  "+color("NBT-NS, LLMNR & MDNS %s" % settings.__version__, 3, 1)
	print ""
	print color('[*]', 2, 1) +" Original work by Laurent Gaffie (lgaffie@trustwave.com)"
	print color('[*]', 2, 1) +" To kill this script hit CRTL-C"
	print ""

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
