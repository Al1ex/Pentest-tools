#!/usr/bin/python
# Copyright (c) 2013-2016 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Modified by Arno0x0x for handling NTLM relay to EWS server
#
# Config utilities
#
# Author:
#  Dirk-jan Mollema / Fox-IT (https://www.fox-it.com)
#
# Description:
#     Configuration class which holds the config specified on the 
# command line, this can be passed to the tools' servers and clients
class NTLMRelayxConfig:
	def __init__(self):
		self.daemon = True
		self.domainIp = None
		self.machineAccount = None
		self.machineHashes = None
		self.target = None
		self.ewsBody = None
		self.ewsRequest = None
		self.ewsFolder = None
		self.ewsDestAddress = None
		self.ewsHomePageURL = None
		self.mode = None
		self.redirecthost = None
		self.outputFile = None
		self.attacks = None
		self.lootdir = None
		self.randomtargets = False
		
	def setOutputFile(self,outputFile):
		self.outputFile = outputFile

	def setTargets(self, target):
		self.target = target

	def setEWSParameters(self, ewsBody, ewsRequest, ewsFolder, ewsDestAddress, ewsHomePageURL):
		self.ewsBody = ewsBody
		self.ewsRequest = ewsRequest
		self.ewsFolder = ewsFolder
		self.ewsDestAddress = ewsDestAddress
		self.ewsHomePageURL = ewsHomePageURL
		
	def setDomainAccount( self, machineAccount,  machineHashes, domainIp):
		self.machineAccount = machineAccount
		self.machineHashes = machineHashes
		self.domainIp = domainIp
	
	def setMode(self,mode):
		self.mode = mode

	def setAttacks(self,attacks):
		self.attacks = attacks

	def setLootdir(self,lootdir):
		self.lootdir = lootdir
