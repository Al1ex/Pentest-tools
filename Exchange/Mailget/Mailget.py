#!/usr/bin/env python
#-*- coding:utf-8 -*-
import pinyin
import requests
import json
import argparse
import sys
from urllib import unquote
import csv
import codecs
import re
reload(sys)
sys.setdefaultencoding("utf-8")

#设置账号密码及hunter的api key
api_key = ""  # Hunter API key
pa = ""  # enter pa, example:+86
phone = "" 	# enter username here
password = ""  # enter password here

parser = argparse.ArgumentParser(description='Discovery Maimai')
parser.add_argument('-d', '--domain', help='The domain want to search')
parser.add_argument('-cn', '--comname',
                    help='The company name（example:饿了么）')
parser.add_argument(
    '-o', '--output', help='Output file (do not include extentions)')
parser.add_argument('-pr', '--prefix', default='auto',
                    help='Select a prefix for e-mail generation (auto,full,firstlast,firstmlast,flast,first.last,fmlast,lastfirst)')
args = parser.parse_args()
domain = args.domain
outname = args.output
comname = args.comname
prefixinput = args.prefix
prefix = ""


#HTML CSS
HTML_CSS = '''
<!-- CSS goes in the document HEAD or added to your external stylesheet -->
<style type="text/css">
table.gridtable {
	font-family: verdana,arial,sans-serif;
	font-size:11px;
	color:#333333;
	border-width: 1px;
	border-color: #666666;
	border-collapse: collapse;
}
table.gridtable th {
	border-width: 1px;
	padding: 8px;
	border-style: solid;
	border-color: #666666;
	background-color: #dedede;
}
table.gridtable td {
	border-width: 1px;
	padding: 8px;
	border-style: solid;
	border-color: #666666;
	background-color: #ffffff;
}
</style>

<!-- Table goes in the document BODY -->
<table class="gridtable">
<tr><th>头像</th><th>姓名</th><th>邮箱</th><th>职位</th><th>地点</th></tr>
'''

HTML_END = "</table>"
HTML_BODY = ""
CSV_DATA = []
logo = '''
                _  _               _   
  /\/\    __ _ (_)| |  __ _   ___ | |_ 
 /    \  / _` || || | / _` | / _ \| __|
/ /\/\ \| (_| || || || (_| ||  __/| |_ 
\/    \/ \__,_||_||_| \__, | \___| \__|
                      |___/            
'''
#检查是否包含汉字
def check_contain_chinese(check_str):
    for ch in check_str.decode('utf-8'):
        if u'\u4e00' <= ch <= u'\u9fff':
            return True
    return False

#汉字转换拼音并进行格式转换
def Nametopinyin(name):
    try:
        if check_contain_chinese(name):
            match = re.search('[A-Za-z0-9]+', name)
            if match:
                return None,None,None
            else:
                name.replace(' ', '')
                if len(name)>9:
                    last = pinyin.get(name[0:6], format='strip')
                    mname = pinyin.get(name[6:9],format='strip')
                    first = pinyin.get(name[9:], format='strip')
                elif len(name) > 6:
                    last = pinyin.get(name[0:3], format='strip')
                    mname = pinyin.get(name[3:6], format='strip')
                    first = pinyin.get(name[6:], format='strip')
                else:
                    last = pinyin.get(name[0:3], format='strip')
                    mname = ""
                    first = pinyin.get(name[3:], format='strip')
                return last, mname, first 
        else:
            return name,None,None
    except:
        return None,None,None
#获取邮箱格式
def getprefix(prefix,domain):
        prefix = prefix.lower()
        domain = domain.lower()
        if prefix == "full" or prefix == "firstlast" or prefix == "firstmlast" or prefix == "flast" or prefix == "first" or prefix == "first.last" or prefix == "fmlast" or prefix == "lastfirst":
            print "[*] use input prefix for e-mail generation"
            return prefix
        elif prefix == "auto":
            #自动获取邮箱前缀类型。
            print "[*] Automaticly using Hunter IO to determine best Prefix of \"{}\"".format(domain)
            url = "https://hunter.io/trial/v2/domain-search?offset=0&domain=%s&format=json" % domain
            r = requests.get(url)
            content = json.loads(r.text)
            if "status" in content:
                print "[!] Rate limited by Hunter IO trial"
                url = "https://api.hunter.io/v2/domain-search?domain=%s&api_key=%s" % (
                    domain, api_key)
                #print url
                r = requests.get(url)
                content = json.loads(r.text)
                if "status" in content:
                    print "[!] Rate limited by Hunter IO Key"
            #print content
            prefix = content['data']['pattern']
            print "[!] %s" % prefix
            if prefix:
                prefix = prefix.replace("{", "").replace("}", "")
                if prefix == "full" or prefix == "firstlast" or prefix == "firstmlast" or prefix == "flast" or prefix == "first" or prefix == "first.last" or prefix == "fmlast" or prefix == "lastfirst":
                    print "[+] Found %s prefix" % prefix
                    return prefix
                else:
                    print "[!] Automatic prefix search failed, please insert a manual choice"
            else:
                print "[!] Automatic prefix search failed, please insert a manual choice"
        else:
            print "[!] Incorrect choice, please select a value from (auto,full,firstlast,firstmlast,flast,first.last,fmlast)"
        return None

#脉脉自动登录
def maimailogin(pa,phone,password):
    try:
        session = requests.session()
        login_data={
            'm': phone,
            'p': password,
            'to':'https://maimai.cn/im/',
            'pa': pa
        }
        session.post('https://acc.maimai.cn/login',data=login_data)
        return session
    except:
        print "[-] Login error!"
        exit(0)

#获取账号信息
def getmailinfo(session, comname):
    comname = unquote(comname)
    page = 0
    try:
        while True:
            contactUrl = 'https://maimai.cn/search/contacts?count=5000&page={}&query=&dist=0&company={}&forcomp=1&searchTokens=&highlight=false&school=&me=&webcname=&webcid=&jsononly=1'.format(page,comname)
            res = session.get(contactUrl).text
            jsonObj = json.loads(res)
            contacts = jsonObj['data']['contacts']
            print "[*] Get the {} page of data..".format(page+1)
            handledata(contacts)
            page = page + 1
            if len(contacts) == 0:
                break
    except:
        print "[-] Get data error !"
            
#处理账号信息
def handledata(data):
    for content in data:
        user =""
        name = content['contact']['name']
        avatar = content['contact']['avatar']
        loc = content['contact']['loc']
        compos = content['contact']['compos']
        #print name, avatar, loc, compos
        name = name.encode('utf-8')
        lname, mname, fname = Nametopinyin(name)
        if fname != None:
            if prefix == "full":
                user = '{}{}{}'.format(mname,fname,lname)
            if prefix == "firstlast":
                user = '{}{}{}'.format(mname,fname,lname)
            if prefix == "firstmlast":
                if len(mname) == 0:
                    user = '{}{}{}'.format(mname, fname, lname)
                else:
                    user = '{}{}{}'.format(mname[0],fname, lname)
            if prefix == "flast":
                user = '{}{}'.format(fname[0], lname)
            if prefix == "first.last":
                user = '{}{}.{}'.format(mname,fname,lname)
            if prefix == "fmlast":
                if len(mname) == 0:
                    user = '{}{}{}'.format(mname, fname[0], lname)
                else:
                    user = '{}{}{}'.format(mname[0], fname[0], lname)
            if prefix == "lastfirst":
                user = '{}{}{}'.format(lname,mname,fname)
        elif lname!= None:
            user = lname
        if user !="":
            mail = "{}@{}".format(user,domain)
            writetofile(avatar, mail, name, compos, loc, outname)

#存储信息
def writetofile(avatar, mail, name, compos, loc, outname):
    global HTML_BODY,CSV_DATA
    CSV_TMP = name, compos, loc, mail
    CSV_DATA.append(CSV_TMP)
    HTML_TMP = "<tr><td><img src=\"{}\" width=50 height=50></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n".format(avatar, name, mail, compos, loc)
    HTML_BODY = HTML_BODY+HTML_TMP

def main():
    print logo
    if len(api_key) == 0 or len(phone) == 0 or len(password) == 0 or len(pa)==0:
        print "[!] Please config the file!"
        exit(0)
    if domain == None:
        print "[!] Please input the domain name!"
        exit(0)
    if outname == None:
        print "[!] Please input the outfile name!"
        exit(0)
    if comname == None:
        print "[!] Please input the company name!"
        exit(0)
    global prefix
    prefix = getprefix(prefixinput, domain)
    if prefix == None:
        exit(0)
    print "[*] Trying to login Maimai."
    session =maimailogin(pa, phone, password)
    if session:
        print "[+] Login success ! Begin to get mails !"
    getmailinfo(session, comname)
    #写文件到HTML
    print "[*] Writing HTML Report to {}.html".format(outname)
    html = open('{}.html'.format(outname), 'a+')
    htmldata = HTML_CSS+HTML_BODY+HTML_END
    html.write(htmldata)
    html.close()
    #写文件到csv
    print "[*] Writing CSV Report to {}.csv".format(outname)
    f = open('{}.csv'.format(outname), 'a+')
    f.write(codecs.BOM_UTF8)
    w = csv.writer(f, quoting=csv.QUOTE_NONNUMERIC)
    for line in CSV_DATA:
        w.writerow(line)
    f.close()
    print "[+] Done !"

if __name__ == '__main__':
    main()
