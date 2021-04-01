from __future__ import unicode_literals, print_function
import json
import codecs
import binascii
import getpass
import traceback
import ldap3
import sys
from aclpwn.utils import ldap2domain, get_sam_name, get_domain
from impacket.ldap import ldaptypes
from impacket.uuid import string_to_bin, bin_to_string
from impacket.ldap.ldaptypes import ACCESS_ALLOWED_OBJECT_ACE, LDAP_SID
from ldap3.utils.conv import escape_filter_chars
from ldap3.protocol.microsoft import security_descriptor_control
from ldap3 import BASE
from pprint import pprint

def print_m(string):
    sys.stderr.write('\033[94m[-]\033[0m %s\n' % (string))

def print_o(string):
    sys.stderr.write('\033[92m[+]\033[0m %s\n' % (string))

def print_f(string):
    sys.stderr.write('\033[91m[!]\033[0m %s\n' % (string))

class RestoreException(Exception):
    pass

class RestoreOperation(object):

    def __init__(self, args, restorefile):
        self.args = args
        self.restorefile = restorefile
        self.ldapconnection = None
        self.contextuser = None
        self.passdata = {}
        with codecs.open(restorefile, 'r', 'utf-8') as infile:
            data = json.load(infile)
            try:
                self.config = data['config']
                self.history = data['history']
            except KeyError:
                print_f('JSON is invalid! Not all required fields are present.')

    def establish_connection(self, user):
        domain = self.config['domain']
        # First check if the server was specified explicitly
        if self.args.server:
            server = self.args.server
        # If not, check if the server was specified in the restore data
        elif self.config['server']:
            server = self.config['server']
        # Else, assume DNS is set up properly and we can connect to the domain
        else:
            server = self.config['domain']

        # Todo: get password from command line args
        try:
            password = self.passdata[user]
        except KeyError:
            prompt = 'Please supply the password or LM:NTLM hashes for the account %s: ' % user
            password = getpass.getpass(prompt.encode('utf-8'))
            # Store for further reference
            self.passdata[user] = password

        if domain is None:
            domain = get_domain(user)
        if '@' in user or '.' in user:
            binduser = get_sam_name(user)
        else:
            binduser = user

        ldapserver = ldap3.Server(server, get_info=ldap3.DSA)
        connection = ldap3.Connection(ldapserver, user='%s\\%s' % (domain, binduser), password=password, authentication=ldap3.NTLM)
        if not connection.bind():
            raise RestoreException('Failed to connect to the LDAP server as %s\\%s: %s' % (domain, binduser, str(connection.result)))
        return connection, user

    def rebind_ldap(self, user):
        domain = self.config['domain']

        # Todo: get password from command line args
        try:
            password = self.passdata[user]
        except KeyError:
            prompt = 'Please supply the password or LM:NTLM hashes for the account %s: ' % user
            password = getpass.getpass(prompt.encode('utf-8'))
            # Store for further reference
            self.passdata[user] = password

        if domain is None:
            domain = get_domain(user)
        if '@' in user or '.' in user:
            binduser = get_sam_name(user)
        else:
            binduser = user

        if not self.ldapconnection.rebind('%s\\%s' % (domain, binduser), password, authentication=ldap3.NTLM):
            raise RestoreException('Failed to switch context to %s\\%s: %s' % (domain, binduser, str(self.ldapconnection.result)))

        return user



    def run(self):
        task_map = {
            "add_addmember_privs": RestoreOperation.remove_addmember_privs,
            "add_user_to_group": RestoreOperation.remove_user_from_group,
            "add_domain_sync": RestoreOperation.remove_domain_sync,
            "write_owner": RestoreOperation.remove_owner,
        }
        for task in reversed(self.history):
            taskname = task['operation']
            data = task['data']
            if not data['success']:
                # Skip this task
                print_m('Task %s was not successful, and will be ignored for restore mode', taskname)
                continue
            if not self.ldapconnection:
                self.ldapconnection, self.contextuser = self.establish_connection(task['contextuser'])
            elif self.contextuser != task['contextuser']:
                self.contextuser = self.rebind_ldap(task['contextuser'])
            try:
                restoreop = task_map[taskname]
            except KeyError:
                raise RestoreException('Unsupported restore operation: %s' % restoreop)
            try:
                restoreop(self.ldapconnection, data)
            except RestoreException:
                print_f('Error while running restore operation:')
                # Just show exception for now
                traceback.print_exc()
                if input('Continue? [y/N] ').upper() != 'Y':
                    return

    @staticmethod
    def dacl_remove_ace(secdesc, guid, usersid, accesstype):
        to_remove = None
        binguid = string_to_bin(guid)
        for ace in secdesc['Dacl'].aces:
            sid = ace['Ace']['Sid'].formatCanonical()
            # Is it the correct ACE type?
            if ace['AceType'] != ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE:
                continue
            # Is it the correct SID?
            if sid != usersid:
                continue
            # Does it apply to the correct property?
            if ace['Ace']['ObjectType'] != binguid:
                continue
            # Does it have the correct mask?
            if ace['Ace']['Mask']['Mask'] != accesstype:
                continue
            # We are still here -> this is the correct ACE
            to_remove = ace
            break

        if to_remove:
            # Found! Remove
            secdesc['Dacl'].aces.remove(to_remove)
            return True
        else:
            # Not found
            return False


    @staticmethod
    def remove_addmember_privs(ldapconnection, data):
        # Set SD flags to only query for DACL
        controls = security_descriptor_control(sdflags=0x04)
        usersid = data['target_sid']

        ldapconnection.search(data['target_dn'], '(objectClass=*)', search_scope=BASE, attributes=['SAMAccountName','nTSecurityDescriptor'], controls=controls)
        entry = ldapconnection.entries[0]

        secDescData = entry['nTSecurityDescriptor'].raw_values[0]
        secDesc = ldaptypes.SR_SECURITY_DESCRIPTOR(data=secDescData)

        old_sd = binascii.unhexlify(data['old_sd'])
        if secDescData == old_sd:
            print_m('%s security descriptor is identical to before operation, skipping' % data['target_dn'])
            return True

        new_sd = binascii.unhexlify(data['new_sd'])
        if secDescData != new_sd:
            # Manual operation
            accesstype = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_WRITE_PROP
            if RestoreOperation.dacl_remove_ace(secDesc, 'bf9679c0-0de6-11d0-a285-00aa003049e2', usersid, accesstype):
                print_m('Removing ACE using manual approach')
                replace_sd = secDesc.getData()
            else:
                raise RestoreException('%s security descriptor does not contain the modified ACE. The access may already be restored.' % data['target_dn'])
        else:
            # We can simply restore the old SD since the current SD is identical to the one after our modification
            print_m('Removing ACE using SD restore approach')
            replace_sd = old_sd

        res = ldapconnection.modify(data['target_dn'], {'nTSecurityDescriptor':(ldap3.MODIFY_REPLACE, [replace_sd])}, controls=controls)
        if res:
            print_o('AddMember privileges restored successfully')
            return True
        else:
            raise RestoreException('Failed to restore WriteMember privs on group %s: %s' % (data['target_dn'], str(ldapconnection.result)))

    @staticmethod
    def remove_user_from_group(ldapconnection, data):
        group_dn = data['group_dn']
        user_dn = data['user_dn']

        # Now add the user as a member to this group
        res = ldapconnection.modify(group_dn, {
            'member': [(ldap3.MODIFY_DELETE, [user_dn])]
        })
        if res:
            print_o('Removed membership of %s from %s' % (user_dn, group_dn))
            return True
        else:
            # Unwilling to perform result means we aren't a member
            if ldapconnection.result['result'] == 53:
                print_m('Could not remove %s from group %s since they are not a member, your restore data may be out of date, continuing anyway!' % (user_dn, group_dn))
                # Treat this as a success
                return True
            raise RestoreException('Failed to remove %s from group %s: %s' % (user_dn, group_dn, str(ldapconnection.result)))


    @staticmethod
    def remove_domain_sync(ldapconnection, data):
        # Set SD flags to only query for DACL
        controls = security_descriptor_control(sdflags=0x04)
        usersid = data['target_sid']

        ldapconnection.search(data['target_dn'], '(objectClass=*)', search_scope=BASE, attributes=['SAMAccountName','nTSecurityDescriptor'], controls=controls)

        entry = ldapconnection.entries[0]
        secDescData = entry['nTSecurityDescriptor'].raw_values[0]
        secDesc = ldaptypes.SR_SECURITY_DESCRIPTOR(data=secDescData)

        old_sd = binascii.unhexlify(data['old_sd'])
        if secDescData == old_sd:
            print_m('%s security descriptor is identical to before operation, skipping' % data['target_dn'])
            return True

        new_sd = binascii.unhexlify(data['new_sd'])
        if secDescData != new_sd:
            accesstype = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_CONTROL_ACCESS
            # these are the GUIDs of the get-changes and get-changes-all extended attributes
            if RestoreOperation.dacl_remove_ace(secDesc, '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', usersid, accesstype) and \
               RestoreOperation.dacl_remove_ace(secDesc, '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2', usersid, accesstype):
                print_m('Removing ACE using manual approach')
                replace_sd = secDesc.getData()
            else:
                raise RestoreException('%s security descriptor does not contain the modified ACE. The access may already be restored.' % data['target_dn'])
        else:
            # We can simply restore the old SD since the current SD is identical to the one after our modification
            print_m('Removing ACE using SD restore approach')
            replace_sd = old_sd

        res = ldapconnection.modify(data['target_dn'], {'nTSecurityDescriptor':(ldap3.MODIFY_REPLACE, [replace_sd])}, controls=controls)
        if res:
            print_o('Domain Sync privileges restored successfully')
            return True
        else:
            raise RestoreException('Failed to restore Domain sync privs on domain %s: %s' % (data['target_dn'], str(ldapconnection.result)))


    @staticmethod
    def remove_owner(ldapconnection, data):
        # Set SD flags to only query for owner
        controls = security_descriptor_control(sdflags=0x01)
        usersid = data['old_owner_sid']

        ldapconnection.search(data['target_dn'], '(objectClass=*)', search_scope=BASE, attributes=['SAMAccountName','nTSecurityDescriptor'], controls=controls)
        entry = ldapconnection.entries[0]

        secDescData = entry['nTSecurityDescriptor'].raw_values[0]
        secDesc = ldaptypes.SR_SECURITY_DESCRIPTOR(data=secDescData)
        if secDesc['OwnerSid'].formatCanonical() == usersid:
            print_m('%s is owned by the same user as before exploitation, skipping' % data['target_dn'])
            return True
        secDesc['OwnerSid'] = LDAP_SID()
        secDesc['OwnerSid'].fromCanonical(usersid)

        secdesc_data = secDesc.getData()
        res = ldapconnection.modify(data['target_dn'], {'nTSecurityDescriptor':(ldap3.MODIFY_REPLACE, [secdesc_data])}, controls=controls)
        if res:
            print_o('Owner restore succesful')
            return True
        else:
            # Constraintintersection means we can't change the owner to this SID
            # TODO: investigate why this is and possible workarounds
            if ldapconnection.result['result'] == 19:
                print_f('Failed to change owner of group %s to %s. This is a known limitation, please restore the owner manually.' % (data['target_dn'], usersid))
                # Treat this as a success
                return True
            raise RestoreException('Failed to change owner of group %s to %s: %s' % (data['target_dn'], usersid, str(ldapconnection.result)))
