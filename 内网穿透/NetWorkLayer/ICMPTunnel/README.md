# ICMPTunnel
Create a reverse icmp tunnel to forward tcp traffic,this maybe useful in some lan env
Usage:

Server :
echo 1> /proc/sys/net/ipv4/icmp_echo_ignore_all
python IcmpTunnel_S.py



Client :
python IcmpTunnel_C.py {serverIP} {needConnectIP} {needConnectPort}

![image](http://img.blog.csdn.net/20151230101433639?watermark/2/text/aHR0cDovL2Jsb2cuY3Nkbi5uZXQv/font/5a6L5L2T/fontsize/400/fill/I0JBQkFCMA==/dissolve/70/gravity/Center)
