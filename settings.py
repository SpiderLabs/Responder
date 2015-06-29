import os
import sys
import socket
import utils
import ConfigParser

__version__ = 'Responder 2.2'

class Settings:
	
	def __init__(self):
		self.ResponderPATH = os.path.dirname(__file__)
		self.Responder_IP = '0.0.0.0'

	def __str__(self):
		ret = 'Settings class:\n'
		for attr in dir(self):
			value = str(getattr(self, attr)).strip()
			ret += "    Settings.%s = %s\n" % (attr, value)
		return ret

	def toBool(self, str):
		return True if str.upper() == 'ON' else False

	def populate(self, options):

		if options.Responder_IP is None:
			print utils.color("Error: -i mandatory option is missing", 1, 0)
			sys.exit(-1)

		# Config parsing
		config = ConfigParser.ConfigParser()
		config.read(os.path.join(self.ResponderPATH, 'Responder.conf'))

		# Servers
		self.HTTP_On_Off = self.toBool(config.get('Responder Core', 'HTTP'))
		self.SSL_On_Off	 = self.toBool(config.get('Responder Core', 'HTTPS'))
		self.SMB_On_Off	 = self.toBool(config.get('Responder Core', 'SMB'))
		self.SQL_On_Off	 = self.toBool(config.get('Responder Core', 'SQL'))
		self.FTP_On_Off	 = self.toBool(config.get('Responder Core', 'FTP'))
		self.POP_On_Off	 = self.toBool(config.get('Responder Core', 'POP'))
		self.IMAP_On_Off = self.toBool(config.get('Responder Core', 'IMAP'))
		self.SMTP_On_Off = self.toBool(config.get('Responder Core', 'SMTP'))
		self.LDAP_On_Off = self.toBool(config.get('Responder Core', 'LDAP'))
		self.DNS_On_Off	 = self.toBool(config.get('Responder Core', 'DNS'))
		self.Krb_On_Off	 = self.toBool(config.get('Responder Core', 'Kerberos'))

		# Log
		self.SessionLog	     = config.get('Responder Core', 'SessionLog')
		self.Log1Filename    = os.path.join(self.ResponderPATH, self.SessionLog)
		self.Log2Filename    = os.path.join(self.ResponderPATH, 'logs', 'LLMNR-NBT-NS.log')
		self.AnalyzeFilename = os.path.join(self.ResponderPATH, 'logs', 'Analyze-LLMNR-NBT-NS.log')

		# HTTP Options
		self.Exe_On_Off		  = config.get('HTTP Server', 'Serve-Exe').upper()
		self.Exec_Mode_On_Off = config.get('HTTP Server', 'Serve-Always').upper()
		self.Html_Filename	  = config.get('HTTP Server', 'HtmlFilename')
		self.Exe_Filename	  = config.get('HTTP Server', 'ExeFilename')
		self.WPAD_Script	  = config.get('HTTP Server', 'WPADScript')
		self.HTMLToServe	  = config.get('HTTP Server', 'HTMLToServe')

		# SSL Options
		self.SSLKey	     = config.get('HTTPS Server', 'SSLKey')
		self.SSLCert	 = config.get('HTTPS Server', 'SSLCert')

		# Respond to hosts
		self.RespondTo			= filter(None, [x.upper().strip() for x in config.get('Responder Core', 'RespondTo').strip().split(',')])
		self.RespondToName		= filter(None, [x.upper().strip() for x in config.get('Responder Core', 'RespondToName').strip().split(',')])
		self.DontRespondTo		= filter(None, [x.upper().strip() for x in config.get('Responder Core', 'DontRespondTo').strip().split(',')])
		self.DontRespondToName	= filter(None, [x.upper().strip() for x in config.get('Responder Core', 'DontRespondToName').strip().split(',')])
		
		print self.DontRespondTo

		# CLI options
		self.Responder_IP	 = options.Responder_IP
		self.LM_On_Off		 = options.LM_On_Off
		self.WPAD_On_Off	 = options.WPAD_On_Off
		self.Wredirect		 = options.Wredirect
		self.NBTNSDomain	 = options.NBTNSDomain
		self.Basic			 = options.Basic
		self.Finger_On_Off	 = options.Finger
		self.Interface		 = options.Interface
		self.Verbose		 = options.Verbose
		self.Force_WPAD_Auth = options.Force_WPAD_Auth
		self.Upstream_Proxy  = options.Upstream_Proxy
		self.AnalyzeMode	 = options.Analyze
		self.CommandLine	 = str(sys.argv)

		self.IP_aton		 = socket.inet_aton(self.Responder_IP)
		self.Os_version		 = sys.platform

		if self.HTMLToServe == None:
			self.HTMLToServe = ''

		if self.Interface != "Not set":
			self.BIND_TO_Interface = self.Interface

		else:
			self.BIND_TO_Interface = "ALL"

		# Challenge
		self.NumChal	 = config.get('Responder Core', 'Challenge')

		if len(self.NumChal) is not 16:
			print utils.color("The challenge must be exactly 16 chars long.\nExample: -c 1122334455667788", 1, 0)
			sys.exit(-1)

		self.Challenge = ""
		for i in range(0, len(self.NumChal),2):
			self.Challenge += self.NumChal[i:i+2].decode("hex")

def init():
	global Config
	Config = Settings()