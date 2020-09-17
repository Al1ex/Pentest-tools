Pwdump v7.1  - http://www.tarasco.org
------------------------------------

Notes:
------

pwdump7 must be executed as an administrator, as the disk device must be accessed.

If running for an offline attack you can specify the SAM and SYSTEM registry hives with the -s flag.


package signatures:
--------------------

openssl dgst -sha1 libeay32.dll
SHA1(libeay32.dll)= 5dc616241164944ee9b2a6cd567dac00af49b238

openssl dgst -sha1 PwDump7.exe
SHA1(PwDump7.exe)= 93a2d7c3a9b83371d96a575c15fe6fce6f9d50d3