using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.DirectoryServices;

namespace SharpADFindDemo
{
    class Program
    {
        static void ShowUsage()
        {
            string Usage = @"
SharpADFindDemo
Use to export the AD data by LDAP.
Complie:
      C:\Windows\Microsoft.NET\Framework64\v3.5\csc.exe SharpADFindDemo.cs /r:System.DirectoryServices.dll
      or
      C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe SharpADFindDemo.cs /r:System.DirectoryServices.dll
Usage:
      SharpADFindDemo <LDAP ServerIP> <user> <password> <command>
command:
- user
- machine
- group
- ou
- username
- machinename
- groupname
- ouname
Note:The maxsize is 1000.
Eg:
      SharpADFindDemo.exe 192.168.1.1 test1 password1 user
";
            Console.WriteLine(Usage);
        }


        static void Main(string[] args)
        {
            if (args.Length != 4)
            {
                ShowUsage(); 
                System.Environment.Exit(0);
            }
            try
            {
                string q = null;
                if (args[3] == "user" || args[3] == "username")
                    q = "(&(objectCategory=person))";
                else if(args[3] == "machine" || args[3] == "machinename")
                    q = "(&(objectCategory=computer))";
                else if(args[3] == "group" || args[3] == "groupname")
                    q = "(&(objectCategory=group))";
                else if(args[3] == "ou" || args[3] == "ouname")
                    q = "(&(objectCategory=organizationalUnit))"; 
                else
                {
                    Console.WriteLine("[!] Wrong parameter");
                    System.Environment.Exit(0);
                }
                Console.WriteLine("[*] Querying LDAP://{0}", args[0]);
                Console.WriteLine("[*] Querying: {0}", q);
                DirectoryEntry de = new DirectoryEntry("LDAP://" + args[0],args[1],args[2]);
                DirectorySearcher ds = new DirectorySearcher(de);
                ds.Filter = q;
                SearchResultCollection rs = ds.FindAll();
                foreach (SearchResult r in rs)
                {  
                    if(args[3].Contains("name"))
                        Console.WriteLine(r.GetDirectoryEntry().Name.ToString());
                    else
                    {
                        ResultPropertyCollection rprops = r.Properties;
                        string prop = null;
                        foreach (string name in rprops.PropertyNames)
                        {
                            foreach (object vl in rprops[name])
                            {
                                prop = name + ":" + vl.ToString();
                                Console.WriteLine(prop);
                            }
                        }
                        Console.WriteLine("-----");  
                    }    
                }
                Console.WriteLine("Total:"+rs.Count);  
            }
            catch (Exception e)
            {
                Console.WriteLine("[!] ERROR: {0}", e.Message);
            }
        }
    }
}