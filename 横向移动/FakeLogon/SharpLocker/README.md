# SharpLocker

SharpLocker helps get current user credentials by popping a fake Windows lock screen, all output is sent to Console which works perfect for Cobalt Strike. It is written in C# to allow for direct execution via memory injection using techniques such as execute-assembly found in Cobalt Strike or others, this method prevents the executable from ever touching disk. It is NOT intended to be compilled and run locally on a device. 

## What SharpLocker is
* A .NET application that is supposed to be run in memory on a target device

## What SharpLocker is NOT
* A password stealing tool that emails plain text credentials
* An executable that is supposed to be double clicked

## Works
* Single/Multiple Monitors
* Windows 10
* Main monitor needs to be 1080p otherwise the location of the elements are wrong

![Working SharpLocker](https://github.com/Pickfordmatt/SharpLocker/blob/master/sharplocker.png?raw=true)

## How to
* Compile SharpLocker from source via VisualStudio etc
* Within a Cobalt Strike implant run execute-assembly C:/{location of exe}
* Pray and wait for creds

## Credits 
- NetNTLMv2PasswordChecker [opdsealey](https://github.com/opdsealey/NetNTLMv2PasswordChecker)