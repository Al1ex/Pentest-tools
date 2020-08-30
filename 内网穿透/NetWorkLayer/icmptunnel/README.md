
**icmptunnel** is a tool to tunnel IP traffic within ICMP echo request and response (ping) packets. It’s intended for bypassing firewalls in a semi-covert way, for example when pivoting inside a network where ping is allowed. It might also be useful for egress from a corporate network to the Internet, although it is quite common for ICMP echo traffic to be filtered at the network perimeter.

While there are a couple of existing tools which implement this technique, icmptunnel provides a more reliable protocol and a mechanism for tunneling through stateful firewalls and NAT.

##### Compiling:

The tool uses a plain Makefile to compile and install.

Use `make` to compile icmptunnel.

##### Quickstart:

First, disable ICMP echo responses on both the client and server. This prevents the kernel from responding to ping packets itself.

    # echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all

On the server-side, start icmptunnel in server mode, and assign an IP address to the new tunnel interface.

    # ./icmptunnel –s
    opened tunnel device: tun0
    (ctrl-z)
    # bg
    # /sbin/ifconfig tun0 10.0.0.1 netmask 255.255.255.0

On the client-side, point icmptunnel at the server, and assign an IP address.

    # ./icmptunnel <server>
    opened tunnel device: tun0
    connection established.
    (ctrl-z)
    # bg
    # /sbin/ifconfig tun0 10.0.0.2 netmask 255.255.255.0

At this point, you should have a functioning point-to-point tunnel via ICMP packets. The server side is 10.0.0.1, and the client-side is 10.0.0.2. On the client, try connecting to the server via SSH:

    # ssh root@10.0.0.1
    Password:

To use the remote server as an encrypted SOCKS proxy:

    # ssh -D 8080 -N root@10.0.0.1
    Password:

Now point your web browser at the local SOCKS server.

##### Further Information

See `./icmptunnel -h` for a list of options.

##### Bugs

Please report any bugs on the Github project page at:

https://github.com/jamesbarlow/icmptunnel/issues
