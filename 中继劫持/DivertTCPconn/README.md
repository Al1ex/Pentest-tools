divertTCPconn
============
Author: Arno0x0x - [@Arno0x0x](http://twitter.com/Arno0x0x)

This program is a fork of [hwfwpass](https://github.com/MRGEffitas/hwfwbypass) and simply proposes a slight modification in
the way it runs. I made this fork to fit my specific needs which required a slight rewriting of the initial hwfwpass code.

DivertTCPconn relies on the [windivert library](https://reqrypt.org/windivert.html) and must be run with administrator rights
on a Windows system of any kind.

What 'divertTCPconn' does
-------------------------
DivertTCPconn captures TCP incoming traffic on any network interface and, based on the TCP destination port, diverts the traffic to another local TCP port.

[WARNING]: **divertTCPconn only works on TCP connection**

Example: To divert incoming traffic initially aimed at port TCP-80 to another TCP port, for instance 8080:

	c:\> divertTCPconn 80 8080


In which circumstances can it be useful
-------------------------
You can use this trick in a few situations:
1. 	When certain local firewalls (eg: ZenWorks) blocks traffic to TCP port (eg: 445), divertTCPconn captures traffic before it reaches the local firewall
	and can then be redirected to another local port of your choice
2.	When a local service is already running on the local machine and is listening on a port you want to use (because, say it's the
	only port opened through another firewall you need to pass traffic through),divertTCPconn captures the traffic before the actual
	service and can then be redirected to another local port of your choice
3.	To screw things up like redirecting SSH or RDP traffic to a dumb port :-)

	
Usage
-------------------------
divertTCPconn original_dstport new_dstport [disablechecksum] [debug]

Examples:

	c:\> divertTCPconn 445 8445 
	
	c:\> divertTCPconn 8081 2020 disablechecksum debug

*disablechecksum*: when this parameter is set, it will disable the calculation of the TCP or IP checksums. 
It is useful when the network adapter driver does the checksum calculations (offload).

*debug*: print debug info on the screen about the original and modified traffic.

Release binary
-------------------------
The provided release binaries (compiled_binaries folder) should be good to go an any Windows system, they come along with the required DLL.


Compilation notes
-------------------------
In case you want to compile it by yourself, just open the Visual Studio solution file, it should compile straight away as all libs and dependencies are included.

You might want to update the WinDivert library:
* Download most recent WinDivert lib from the [official website](http://reqrypt.org/windivert.html)
* Update packages in windivert_32_lib or windivert_x64_lib directories
* Copy the compiled windivert files (dll, sys) to the compiled divertTCPconn directory (32/64, debug/release)



Known problems, errors:
-------------------------
	error: failed to open the WinDivert device (5)

Solution: Start the executable with administrator level privileges. Check if the DLL and SYS file is in the same directory. 

	error: msvcrxxx.dll is missing:

Solution: Download the corresponding Microsoft Visual Studio redistributable files, and either install it, or put the DLL's in the same directory where the divertTCPconn binary is.
* msvcr110.dll -> Visual studio 2012
* msvcr120.dll -> Visual studio 2013

Always install the same architecture (32/64 bit) of the DLL as it is the binary.
Additional information: the windivert dll file has been compiled with VS2013, and divertTCPconn has been compiled with VS2015

Limitations:
-------------------------
1. The bind shell should listen on the same interface where the service with original_dstport listens. The driver can't forward the traffic to the "non-existent" loopback interface.
2. Only TCP traffic is supported at the moment.