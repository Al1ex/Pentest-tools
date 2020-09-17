________                          __            __________          ________
\_____  \   __ __ _____  _______ |  | __  ______\______   \__  _  __\______ \   __ __   _____  ______
 /  / \  \ |  |  \\__  \ \_  __ \|  |/ / /  ___/ |     ___/\ \/ \/ / |    |  \ |  |  \ /     \ \____ \
/   \_/.  \|  |  / / __ \_|  | \/|    <  \___ \  |    |     \     /  |    `   \|  |  /|  Y Y  \|  |_> >
\_____\ \_/|____/ (____  /|__|   |__|_ \/____  > |____|      \/\_/  /_______  /|____/ |__|_|  /|   __/
       \__>            \/             \/     \/                             \/              \/ |__|
                                                                           v0.2b -<(QuarksLab)>-


0 / INTRO
=========

Quarks PwDump is a native Win32 tool to extract credentials from Windows operating systems.

It currently extracts :
 - Local accounts NT/LM hashes + history
 - Domain accounts NT/LM hashes + history
 - Cached domain password
 - Bitlocker recovery information (recovery passwords & key packages) 
 
Supported OS : XP/2003/Vista/7/2008/8

Why another hash dumper?
 - No tools can actually dump all kind of hash, a combination of tools is always needed.
 - We encounter some rare crash with libesedb library and some NTDS.dit files.
 - We think it's safer to directly use Microsoft JET/ESE API for parsing databases originally
   built with same functions.
 - Bitlocker case is added even if some specific Microsoft tools could be used to dump those information.
   (Active Directory addon or VBS scripts)
 
We would like to greet NTDS hash dump (Csaba Barta) and creddump author for their excellent work.

Also it is still in beta test.


1 / USAGE
=========

Here it is how you can use Quarks PWDump:

quarks-pwdump.exe <options>
	Options : 
	-dhl  --dump-hash-local
	-dhdc --dump-hash-domain-cached
	-dhd  --dump-hash-domain (NTDS_FILE must be specified)
	-db   --dump-bitlocker (NTDS_FILE must be specified)
	-nt   --ntds-file FILE
	-hist --with-history (optional)
	-t    --output-type JOHN/LC (optional, if no=>JOHN)
	-o    --output FILE (optional, if no=>stdout)
	Example: quarks-pwdump.exe --dump-hash-domain --with-history

Dump options must be user all at once.
In all cases, the tool must be executed on the targeted operating system.

Do not forget to always put NTDS.dit filepath at the end of the command line for involved options.

Some command examples:

 - Dump domain hashes from NTDS.dit with its history
   #quarks-pwdump.exe --dump-hash-domain --with-history

- Dump local account hashes to LC format
   #quarks-pwdump.exe --dump-hash-local --output-type LC
   
- Dump domain hashes from NTDS.dit with its history
   #quarks-pwdump.exe --dump-bitlocker --output c:\bitlocker.txt --ntds-file c:\ntds.dit

All features require administrator privileges.


2 / TECHNICAL APPROACH
======================

 - Bitlocker and domain accounts information are extracted offline from NTDS.dit
   (see next section for NTDS file recovery)
   Everything must be done on domain controller. No code injection or service installation.
   It's not currently full offline dump cause Quarks PwDump is dynamically linked with ESENT.dll
   which differs between Windows version. For example, it's not possible to parse Win 2008 ntds.dit
   file from XP.
   
  - For Bitlocker case, Quarks PwDump can retrieve these information :
    * Recovery password: it's a 48-digits passphrase which allow a user to mount its partition if
	  password has been lost. This password can be user in Bitlocker recovery console.
	* Key Package : it's a binary keyfile which allow an user to decipher data on a damaged disk or
	  partition. It can be used with Microsoft tools, especially Bitlocker Repair Tool.
	  
	  For each entry found in NTDS.dit, Quarks PwDump show recovery password to STDOUT and keyfiles 
	  (key packages) are stored to separate files for each recovery GUID.
	  {GUID_1}.pk, {GUID_2}.pk,...
 
  - Local account and cached information are extracted live from SAM and SECURITY hive in a proper
    way without code injection/service. In fact, we use native registry API, especially RegSaveKey() and 
	RegLoadKey() function which require BACKUP and RESTORE privileges. Next we mount SAM/REGISTRY hives
	on a diffrent mount point and change all keys ACL in order to extend privileges to Administrator
	group and not LocalSystem only.
	That's why we choose to work on a backup to preserve system integrity.


3 / NOTES ON NTDS.DIT PARSING
=============================

1. Windows 2008

Microsoft recently implements VSS (Volume Shadow Copy Service) which allow an administrator to make
filesystem snapshots while the operating is running and writing to current backuped files.

Here is a way to backup NTDS.dit file while a domain controller is running:

 #ntdsutil
 #snapshot
 #activate instance ntds
 #create
 #mount {GUID}
 #copy c:\MOUNT_POINT\WINDOWS\NTDS\NTDS.dit c:\NTDS_saved.dit
 #unmount {GUID}
 #quit
 #quit

If AD server hasn't the "AD DS role", you have to use dsdbutil.exe command in the same way.


2. Windows 2003

On this version, VSS has been implemented but not NTDS-type snapshots.
But you can use ntbackup tool, here is the procedure:

- Launch NTBACKUP gui
- Use backup wizard (advanced)
- Choose to save system state only and choose output filename
- Wait some minutes
- Use restore wizard (advanced)
- Choise your backup, click next and use advanced button
- Choose to restore file on another location (c:\tmp\ for example)
- Choose to overwrite everything and next uncheck all restoration parameters
- Validate and wait some minutes
- Open a command shell to "c:\tmp\Active Directory"
- We need to repair the database with this command 
 #esentutl /p ntds.dit
- Validate warning and wait some minutes

ntds.dit file can now be used with quarkspwdump.



4 / TODO & ROAD MAP
===================
 
 - Clean code, especially local account history dump
 - Make NTDS parsing system independant (esent.dll)
 - Use VSS COMM API to directly copy NTDS.dit file from our tool
 - Make tests on more environments with different configuration (NTLM storage GP, history size...)
 - Parsing specific Bitlocker TPM owner information in NTDS.dit
 - Make the tool working full offline (from mounted image disk for example)
 

contact@quarkslab.com
