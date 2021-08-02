using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.Exchange.WebServices;
using Microsoft.Exchange.WebServices.Data;
using System.IO;
using System.Globalization;
using System.Linq;


namespace ConsoleApplication15
{

        public class AccessInfo
    {
        public string UserName;
        public string Password;
        //public string Domain;
        public string ServerUrl;
        //public string Email;
    }

    class Program
    {


        public static string ExUrl;
        public static string Uname;
        public static string Pwd;
        public static WellKnownFolderName aaaa;
        public static FindItemsResults<Item> findResultsaa;
        public static void SaveEmailAttachment(ExchangeService service, string Box, string Filterstring=null)
        {

            if (Box == "SentItems")
            {
                aaaa = WellKnownFolderName.SentItems;
            }
            else
            {
                aaaa = WellKnownFolderName.Inbox;
            }



            Output(@".\inbox\log.txt", "==============================mail========================" + Box);
            int num = 0;
            //创建过滤器, 条件为邮件未读. 
            //SearchFilter sf = new SearchFilter.IsEqualTo(EmailMessageSchema.IsRead, true);

            //查找Inbox,加入过滤器条件,结果10条 
            //WellKnownFolderName.Parse(WellKnownFolderName.1);

            ItemView view = new ItemView(999999); //-- 显示条数

          
                SearchFilter.ContainsSubstring subjectFilter = new SearchFilter.ContainsSubstring(ItemSchema.Body, Filterstring, ContainmentMode.Substring, ComparisonMode.IgnoreCase);
                Folder inbox = Folder.Bind(service, aaaa);// inbox  SentItems
                view.PropertySet = new PropertySet(BasePropertySet.IdOnly);



                if (Filterstring==null)
                {
                    findResultsaa = inbox.FindItems(view);
                    
                }
                else if (Filterstring!=null)
                {
                    findResultsaa = inbox.FindItems(subjectFilter, view);
                    

                }


                FindItemsResults<Item> findResults = findResultsaa;

            
   


            foreach (Item item in findResults.Items)
            {
                num = num + 1;
                PropertySet props = new PropertySet(EmailMessageSchema.MimeContent,EmailMessageSchema.Subject);//这个地方设置属性

                // This findResults.Items in a GetItem call to EWS.
                var email = EmailMessage.Bind(service, item.Id, props);

                string path=@".\inbox\"+Box+"\\";

                if (Directory.Exists(path) == false)//如果不存在就创建file文件夹
                {
                    Directory.CreateDirectory(path);
                }


                string emlFileName = path + num + ".eml";

                //Console.WriteLine(item.Id);

                //string mhtFileName = @"C:\tmp\item.Id.mht";

                // Save as .eml.
                using (FileStream fs = new FileStream(emlFileName, FileMode.Create, FileAccess.Write))
                {
                    fs.Write(email.MimeContent.Content, 0, email.MimeContent.Content.Length);
                }
                Console.WriteLine(Box+"Email title name: " + email.Subject + ".eml");
                Output(@".\inbox\log.txt", num + "^^^^^" + email.Subject);

                // Save as .mht.
                //using (FileStream fs = new FileStream(mhtFileName, FileMode.Create, FileAccess.Write))
                //{
                //    fs.Write(email.MimeContent.Content, 0, email.MimeContent.Content.Length);
                //}
            }
        }

        public static void Output(string localFilePath, string data)
        {
            try
            {
                if (!File.Exists(localFilePath))
                {
                    FileStream fs1 = new FileStream(localFilePath, FileMode.Create, FileAccess.Write);
                    fs1.Close();
                    StreamWriter sw = new StreamWriter(localFilePath, true);
                    sw.WriteLine(data);
                    sw.Close();
                }
                else
                {
                    StreamWriter sw = new StreamWriter(localFilePath, true);
                    sw.WriteLine(data);
                    sw.Close();
                }
            }
            catch
            {

            }
        }

        public static void Sendmail(ExchangeService service, string Subtitle, string Tomail,string MBody)
        {
            EmailMessage message = new EmailMessage(service);
            // 邮件主题
            message.Subject = Subtitle;
            message.Body = new MessageBody();
            // 指定发送邮件的格式，可以是Text和HTML格式
            message.Body.BodyType = BodyType.HTML;

            string Bhtml=@""+MBody;
            using (FileStream fsRead = new FileStream(Bhtml, FileMode.Open))
            {
                int fsLen = (int)fsRead.Length;
                byte[] heByte = new byte[fsLen];
                int r = fsRead.Read(heByte, 0, heByte.Length);
                string myStr = System.Text.Encoding.UTF8.GetString(heByte);
                //Console.WriteLine(myStr);
                message.Body.Text = myStr;
                //Console.ReadKey();
            }



            // 邮件内容
            //message.Body.Text = Body;
            // 可以添加多个邮件人.也可以添加一个集合，用
            // message.ToRecipients.AddRange(IList toEmailAddress_list)
            message.ToRecipients.Add(Tomail);
            //message.Attachments.AddFileAttachment("a.zip");//附件

            //message.save();// 保存草稿

            message.Send(); // 只发送不保存已发送邮件
            //message.SendAndSaveCopy(); // 发送并保存已发送邮件 


        }


        public static void ListContacts(ExchangeService service)
        {

            Output(@".\inbox\log.txt", "========================ListContacts========================");

            try
            {
                var offset = 0;
                const int pageSize = 100000;
                var view = new ItemView(pageSize, offset);
                var f1 = service.FindItems(WellKnownFolderName.Contacts, view);

                foreach (Item itemcontacts in f1.Items)
                {
                    var contacts = (Contact)(itemcontacts);

                    //System.Diagnostics.Trace.WriteLine(contacts.DisplayName);
                    Console.WriteLine(contacts.DisplayName + ":" + contacts.EmailAddresses[0]);
                    Output(@".\inbox\log.txt", contacts.DisplayName + ":" + contacts.EmailAddresses[0]);
                }
            }
            catch
            {

                Console.WriteLine("no fund _or_ Too new version");
            }
        }

        public static ExchangeService ConnectToExchangeService(AccessInfo Info)
        {

            //ExchangeService版本为2010 
            // changeService service = new ExchangeService();

            //给出Exchange Server的URL http://xxxxxxx
            //service.Url = new Uri(Info.ServerUrl);

            //根据完整邮箱自动发现地址
            // service.AutodiscoverUrl(Info.Email);

            // service = new ExchangeService();
            ExchangeService service = new ExchangeService();
            //service.UseDefaultCredentials = true;

            //参数是用户名,密码,域 
            //service.Credentials = new WebCredentials(Info.UserName, Info.Password, Info.Domain);


            if ((Info.UserName == null) & (Info.Password == null))
            {
                service.UseDefaultCredentials = true;
            }
            else
            {
                service.Credentials = new WebCredentials(Info.UserName, Info.Password);
            }

            System.Net.ServicePointManager.ServerCertificateValidationCallback =
                   ((sender, certificate, chain, sslPolicyErrors) => true); // 解决https证书
            //service.Url = new Uri(Url);
            service.Url = new Uri(ExUrl);
            return service;
        }

//        public static void SetFolderHomePage(IEnumerable<string> pathFragments, string url, ExchangeService service)
        public static void SetFolderHomePage(string url, ExchangeService service,string Option)
        {
            var folderWebviewinfoProperty = new ExtendedPropertyDefinition(14047, MapiPropertyType.Binary);
            var root = Folder.Bind(service, WellKnownFolderName.Inbox);

            var targetFolder = root;
            //foreach (var fragment in pathFragments)
            //{
               // var result = service.FindFolders(targetFolder.Id, new SearchFilter.IsEqualTo(FolderSchema.DisplayName, fragment), new FolderView(1));
            //}


               targetFolder.SetExtendedProperty(folderWebviewinfoProperty, EncodeUrl(url));
               targetFolder.Update();
             if (Option == "Reset")
            {
                targetFolder.RemoveExtendedProperty(folderWebviewinfoProperty);
                 targetFolder.Update();
                
                //targetFolder.Update();
                 Console.WriteLine("delete Outlook Homepage url ok");
            }
             else
             {
                 Console.WriteLine("Set Outlook Homepage url ok");
             }
           
        }

        public static byte[] EncodeUrl(string url)
        {
            var writer = new StringWriter();
            var dataSize = ((ConvertToHex(url).Length / 2) + 2).ToString("X2");

            writer.Write("02"); // Version
            writer.Write("00000001"); // Type
            writer.Write("00000001"); // Flags
            writer.Write("00000000000000000000000000000000000000000000000000000000"); // unused
            writer.Write("000000");
            writer.Write(dataSize);
            writer.Write("000000");
            writer.Write(ConvertToHex(url));
            writer.Write("0000");

            var buffer = HexStringToByteArray(writer.ToString());
            return buffer;
        }

        public static string ConvertToHex(string input)
        {
            return string.Join(string.Empty, input.Select(c => ((int)c).ToString("x2") + "00").ToArray());
        }

        private static byte[] HexStringToByteArray(string input)
        {
            return Enumerable
                .Range(0, input.Length / 2)
                .Select(index => byte.Parse(input.Substring(index * 2, 2), NumberStyles.AllowHexSpecifier)).ToArray();
        }


        public static void ShowExample()
        {
            string Ua = @"
                       _____      _____ 
                      / _ \ \ /\ / / __|
                      |  __/\ V  V /\__ \
                      \___| \_/\_/ |___/          
                                          Exchange Ews Interface operation
                v1.5 xc
Example:
    SendMail:
        Ews.exe https://y/ews/Exchange.asmx -Sendmail -T ""你好"" -TM s@m.com -B html.txt

        Ews.exe https://y/ews/Exchange.asmx -U x@x.com -P 123 -Sendmail -T ""你好"" -TM s@m.com -B html.txt

    Get Inbox|SentItems Mail:
    
        Ews.exe https://y/ews/Exchange.asmx -MType Inbox|SentItems

        Ews.exe https://y/ews/Exchange.asmx -MType Inbox|SentItems -Filterstring ""VPN""

        Ews.exe https://y/ews/Exchange.asmx -U x@x.com -P 123 -MType Inbox|SentItems -Filterstring ""VPN""

    Set Inbox Homepage:
        EWS.exe https://y/ews/Exchange.asmx -Purl http://sb/s.html -Type Reset|Set
        EWS.exe https://y/ews/Exchange.asmx -U x@x.com -P 123 -Purl http://sb/s.html -Type Reset|Set
";
            Console.WriteLine(Ua);
        } 

        static void Main(string[] args)
        {



            try
            {
                if ((args[1] != "-U"))
                {
                    ExUrl = args[0].ToString();
                    AccessInfo info = new AccessInfo()
                    {
                        ServerUrl = ExUrl
                    };

                    ListContacts(ConnectToExchangeService(info));

                    if ((args[1] == "-Sendmail"))
                    {
                        Console.WriteLine(args[3]);
                        Sendmail(ConnectToExchangeService(info), args[3], args[5], args[7]);

                    }
                    else if ((args[1] == "-MType"))
                    {
                        //Console.WriteLine(args[2]);

                        string MType = args[2];

                        try
                        {
                            if (args[4] != null)
                            {
                                SaveEmailAttachment(ConnectToExchangeService(info), MType, args[4]);

                            }
                        }
                        catch
                        {
                            SaveEmailAttachment(ConnectToExchangeService(info), MType, null);

                        }

                    }
                    else if ((args[1] == "-Purl") && (args[4] != null))
                    {
                        SetFolderHomePage(args[2], ConnectToExchangeService(info), args[4]);
                    }


                }
                else if (args.Length > 4)
                {
                    ExUrl = args[0].ToString();
                    Uname = args[2].ToString();
                    Pwd = args[4].ToString();
                    //string PayloadUrl = args[2].ToString();
                    //string OpTpye = args[4].ToString();

                    AccessInfo info = new AccessInfo()
                    {
                        UserName = Uname,
                        Password = Pwd,
                        //Domain = "contoso.com",
                        ServerUrl = ExUrl
                    };
                    ListContacts(ConnectToExchangeService(info));
                    if ((args[5] == "-Sendmail") && (args[6] == "-T") && (args[8] == "-TM") && (args[10] == "-B"))
                    {
                        string title = args[7];
                        string TM = args[9];
                        string Bhtml = args[11];

                        Sendmail(ConnectToExchangeService(info), title, TM, Bhtml);


                    }



                    if ((args[5] == "-Purl") && (args[7] == "-Type"))
                    {
                        string PayloadUrl = args[6];
                        string OpTpye = args[8];

                        SetFolderHomePage(PayloadUrl, ConnectToExchangeService(info), OpTpye);


                    }


                    if ((args[5] == "-MType"))
                    {
                        string MType = args[6];

                        try
                        {
                            if (args[8] != null)
                            {
                                SaveEmailAttachment(ConnectToExchangeService(info), MType, args[8]);

                            }
                        }
                        catch
                        {
                            SaveEmailAttachment(ConnectToExchangeService(info), MType, null);

                        }



                    }


                }
            }
            catch
            {
                
                ShowExample();
            }



        }




    }
}