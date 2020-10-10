# SharpSecDump
 .Net port of the remote SAM + LSA Secrets dumping functionality of impacket's secretsdump.py.  By default runs in the context of the current user.  Please only use in environments you own or have permission to test against :)
 
 # Usage
 `SharpSecDump.exe -target=192.168.1.15 -u=admin -p=Password123 -d=test.local`
 
 **Required Flags**
 - **-target** - Comma seperated list of IP's / hostnames to scan.  Please don't include spaces between addresses.  Can also dump hashes on the local system by setting target to 127.0.0.1.
 
 **Optional Flags**
- **-u** - Username to use, if you want to use alternate credentials to run. Must use with -p and -d flags
- **-p** - Plaintext password to use, if you want to use alternate credentials to run. Must use with -u and -d flags
- **-d** - Domain to use, if you want to use alternate credentials to run (. for local domain). Must use with -u and -p flags
- **-threads** - Threads to use to concurently enumerate multiple remote hosts (Default: 10)

# Notes
The project has been tested against Win 7,10, Server 2012, and Server 2016.  Older versions (win 2003 / xp) may not work with this tool.

By default, if you're attempting to dump hives from your local system, you'll need to be running from a high-integrity context.  However, this is not necessary when targeting remote systems.

This currently supports SAM + SECURITY registry hive dumping to retrieve cached credential data.  However, it does not support NTDS.dit parsing / dcsync yet.  If you're looking for dcsync functionality in a .Net project I recommend [sharpkatz](https://github.com/b4rtik/SharpKatz).

If a system is configured to disallow RPC over TCP (RPC over named pipe is required -- this is not a default setting) there is a 21s delay before Windows will fall back to RPC/NP, but will still allow the connection. This appears to be a limitation of using API calls that leverage the SCManager to remotely bind to services.  
  
 # Credits
This code is a port of functionality from [impacket](https://github.com/SecureAuthCorp/impacket) by [@agsolino](https://twitter.com/agsolino) and [pypykatz](https://github.com/skelsec/pypykatz) by [@skelsec](https://twitter.com/SkelSec).  All credit goes to them for the original steps to parse and decrypt info from the registry hives.

The registry hive structures used are from [gray_hat_csharp_code](https://github.com/brandonprry/gray_hat_csharp_code) by [@BrandonPrry](https://twitter.com/BrandonPrry).

Finally, the original idea for the script was based on a partial port I was working on of [Posh_SecModule](https://github.com/darkoperator/Posh-SecMod) by [@Carlos_Perez](https://twitter.com/Carlos_Perez), a good chunk of initial SAM parsing code came from that project.
