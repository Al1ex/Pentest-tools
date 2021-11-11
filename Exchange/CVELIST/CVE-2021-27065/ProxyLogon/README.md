# ProxyLogon For Python3
ProxyLogon(CVE-2021-26855+CVE-2021-27065) Exchange Server RCE(SSRF->GetWebShell)
```python
usage:
    python ProxyLogon.py --host=exchange.com --mail=admin@exchange.com
    python ProxyLogon.py --host=exchange.com --mails=./mails.txt
args:
    --host: target's address.
    --mail: exists user's mail.
    --mails: mails file.
```

![](https://github.com/p0wershe11/ProxyLogon/blob/main/gif.gif)
