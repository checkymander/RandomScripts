using System;
using System.Collections.Generic;
using System.Linq;
using System.Diagnostics;
using System.IO;
using System.DirectoryServices;
using System.Runtime.InteropServices;
using System.DirectoryServices.AccountManagement;
using System.Windows.Forms;
using System.Collections;
using Microsoft.Win32;
using NetFwTypeLib;
using System.Data;
using System.Text.RegularExpressions;
using System.Security.AccessControl;
using System.Security.Principal;
//http://www.codeproject.com/Articles/18102/Howto-Almost-Everything-In-Active-Directory-Via-C
namespace InfoGather
{
    //Check for Powershell Logging and Windows Event Forwarding.
    //Check Powershell Version

    class Program
    {
        public const int WTS_CURRENT_SESSION = -1;
        //Imports the wtsapi32.dll for RDP session Enumeration
        [DllImport("wtsapi32.dll")]
        static extern int WTSEnumerateSessions(
            IntPtr pServer,
            [MarshalAs(UnmanagedType.U4)] int iReserved,
            [MarshalAs(UnmanagedType.U4)] int iVersion,
            ref IntPtr pSessionInfo,
            [MarshalAs(UnmanagedType.U4)] ref int iCount
        );
        //Struct to query information for each session found
        [DllImport("wtsapi32.dll")]
        public static extern bool WTSQuerySessionInformation(
            System.IntPtr pServer,
            int iSessionID,
            WTS_INFO_CLASS oInfoClass,
            out System.IntPtr pBuffer,
            out uint iBytesReturned
        );
        //Frees the memory used while querying
        [DllImport("wtsapi32.dll")]
        static extern void WTSFreeMemory(
    IntPtr pMemory);

        //Structure for Terminal Service Client IP Address
        [StructLayout(LayoutKind.Sequential)]
        private struct WTS_CLIENT_ADDRESS
        {
            public int iAddressFamily;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 20)]
            public byte[] bAddress;
        }

        //Structure for Terminal Service Session Info
        [StructLayout(LayoutKind.Sequential)]
        private struct WTS_SESSION_INFO
        {
            public int iSessionID;
            [MarshalAs(UnmanagedType.LPStr)]
            public string sWinsWorkstationName;
            public WTS_CONNECTSTATE_CLASS oState;
        }
        public enum WTS_CONNECTSTATE_CLASS
        {
            WTSActive,
            WTSConnected,
            WTSConnectQuery,
            WTSShadow,
            WTSDisconnected,
            WTSIdle,
            WTSListen,
            WTSReset,
            WTSDown,
            WTSInit
        }

        public enum WTS_INFO_CLASS
        {
            WTSInitialProgram,
            WTSApplicationName,
            WTSWorkingDirectory,
            WTSOEMId,
            WTSSessionId,
            WTSUserName,
            WTSWinStationName,
            WTSDomainName,
            WTSConnectState,
            WTSClientBuildNumber,
            WTSClientName,
            WTSClientDirectory,
            WTSClientProductId,
            WTSClientHardwareId,
            WTSClientAddress,
            WTSClientDisplay,
            WTSClientProtocolType,
            WTSIdleTime,
            WTSLogonTime,
            WTSIncomingBytes,
            WTSOutgoingBytes,
            WTSIncomingFrames,
            WTSOutgoingFrames,
            WTSClientInfo,
            WTSSessionInfo,
            WTSConfigInfo,
            WTSValidationInfo,
            WTSSessionAddressV4,
            WTSIsRemoteSession
        }
        [STAThread]
        static void Main(string[] args)
        {
            //lstGroups.ForEach(delegate (String groupName) {
            //   Console.WriteLine("-------------------------------------------------------------------------------");
            //  Console.WriteLine(groupName);
            // Console.WriteLine("-------------------------------------------------------------------------------");
            // GetMembers(groupName);
            //Console.WriteLine("\n");
            //});
            //getLocalGroups();
            //getADMembership();
            //getInstalledApplications();
            //getClipboard();
            //getOSVersion();
            //getBlueTeam();
            //getShares();
            //getUptime();
            //getRDPSessions();
            //getFirewall();
            //checkLogging();
            //checkEventForwarding();

            if (args.Length >= 1)
            {
                foreach (string argument in args)
                {
                    switch (argument)
                    {
                        case "DirectoryOnly":
                            Console.WriteLine("===============================================================================");
                            Console.WriteLine("Searching for interesting files...");
                            Console.WriteLine("===============================================================================");
                            getDirectoryListing("C:\\");
                            break;
                        case "AllChecks":
                            getLocalGroups();
                            //getADMembership();
                            getInstalledApplications();
                            getClipboard();
                            getOSVersion();
                            getBlueTeam();
                            getShares();
                            getUptime();
                            getRDPSessions();
                            getFirewall();
                            checkLogging();
                            //checkEventForwarding();
                            Console.WriteLine("===============================================================================");
                            Console.WriteLine("Searching for interesting files...");
                            Console.WriteLine("===============================================================================");
                            getDirectoryListing("C:\\");
                            break;
                        default:
                            getLocalGroups();
                            //getADMembership();
                            getInstalledApplications();
                            getClipboard();
                            getOSVersion();
                            getBlueTeam();
                            getShares();
                            getUptime();
                            getRDPSessions();
                            getFirewall();
                            checkLogging();
                            //checkEventForwarding();
                            break;
                    }
                }
            }
            else
            {
                //getLocalGroups();
                //getADMembership();
                //getInstalledApplications();
                //getClipboard();
                //getOSVersion();
                //getBlueTeam();
                //getShares();
                //getUptime();
                //getRDPSessions();
                //getFirewall();
                //checkLogging();
                //checkEventForwarding();
                //checkTwoFactor();
                //checkRegistryPrivesc();
                //checkHijackableDLLs();
                //checkUnattended();
                getDirectoryListing("C:\\");
            }
            string a = Console.ReadLine();
        }

        //        static void getOpenPorts()
        //       {
        //          Console.WriteLine("Active Connections");
        //         Console.WriteLine();
        //
        //           Console.WriteLine(" Proto Local Address Foreign Address State PID");
        //          foreach (TcpRow tcpRow in ManagedIpHelper.GetExtendedTcpTable(true))
        //         {
        //            Console.WriteLine(" {0,-7}{1,-23}{2, -23}{3,-14}{4}", "TCP", tcpRow.LocalEndPoint, tcpRow.RemoteEndPoint, tcpRow.State, tcpRow.ProcessId);
        //
        //               Process process = Process.GetProcessById(tcpRow.ProcessId);
        //               if (process.ProcessName != "System")
        //              {
        //                 foreach (ProcessModule processModule in process.Modules)
        //                {
        //                   Console.WriteLine(" {0}", processModule.FileName);
        //              }
        //
        //                   Console.WriteLine(" [{0}]", Path.GetFileName(process.MainModule.FileName));
        //              }
        //             else
        //            {
        //               Console.WriteLine(" -- unknown component(s) --");
        //              Console.WriteLine(" [{0}]", "System");
        //         }
        //
        //                Console.WriteLine();
        //           }
        //      }

        static void checkRegistryPrivesc()
        {
            try
            {
                string key = @"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer";
                //Check if alwaysinstallelevated registry key is set in HKLM:
                using (RegistryKey basekey = Registry.LocalMachine.OpenSubKey(key))
                {
                    if (basekey.GetValue("InstallElevated").ToString() == "1")
                    {
                        Console.WriteLine("InstallElevated found enabled under: " + key);
                    }
                }
            }
            catch
            {

            }
            try
            {
                string key = @"HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer";
                //Check if alwaysinstallelevated registry key is set in HKCU:
                using (RegistryKey basekey = Registry.LocalMachine.OpenSubKey(key))
                {
                    if (basekey.GetValue("InstallElevated").ToString() == "1")
                    {
                        Console.WriteLine("InstallElevated found enabled under: " + key);
                    }
                }
            }
            catch
            {
            }

            //Check if DefaultUserName and DefaultPassword are set in the Resgistry.
            try{
                string key = @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
                using (RegistryKey basekey = Registry.LocalMachine.OpenSubKey(key))
                {
                    if (basekey.GetValue("DefaultDomainName") != null)
                    {
                        Console.WriteLine("Found DefaultDomainName: " + basekey.GetValue("DefaultDomainName").ToString());
                    }
                    if (basekey.GetValue("DefaultUsername") != null)
                    {
                        Console.WriteLine("Found DefaultUsername: " + basekey.GetValue("DefaultUsername").ToString());
                    }
                    if (basekey.GetValue("DefaultPassword") != null)
                    {
                        Console.WriteLine("Found DefaultPassword: " + basekey.GetValue("DefaultPassword").ToString());
                    }
                    if (basekey.GetValue("AltDefaultDomainName") != null)
                    {
                        Console.WriteLine("Found AltDefaultDomainName: " + basekey.GetValue("AltDefaultDomainName").ToString());
                    }
                    if (basekey.GetValue("AltDefaultUsername") != null)
                    {
                        Console.WriteLine("Found AltDefaultUsername: " + basekey.GetValue("AltDefaultUsername").ToString());
                    }
                    if (basekey.GetValue("AltDefaultPassword") != null)
                    {
                        Console.WriteLine("Found AltDefaultPassword: " + basekey.GetValue("AltDefaultPassword").ToString());
                    }
                }

            }
            catch
            {

            }
            //TODO: Modifiable Registry Auto Run- checks for any modifiable binaries/scripts (or their configs) in HKLM autoruns
        }
        static void checkHijackableDLLs()
        {
            Console.WriteLine("===============================================================================");
            Console.WriteLine("Doing DLL Hijacking Checks");
            Console.WriteLine("===============================================================================");
            Console.WriteLine("The following folders are located in the PATH variable and are writeable by the current user");


            //finds potential DLL hijacking opportunities for currently running processes
            //finds service %PATH% DLL hijacking opportunities

            String userPath = Environment.GetEnvironmentVariable("PATH");
            List<string> dirs = userPath.Split(new char[] {';'}, StringSplitOptions.RemoveEmptyEntries).ToList<string>();

            foreach(String dir in dirs)
            {
                try
                {
                    DirectoryInfo di = new DirectoryInfo(dir);
                    DirectorySecurity acl = di.GetAccessControl();
                    AuthorizationRuleCollection rules = acl.GetAccessRules(true, true, typeof(NTAccount));

                    WindowsIdentity currentUser = WindowsIdentity.GetCurrent();
                    WindowsPrincipal principal = new WindowsPrincipal(currentUser);
                    foreach (AuthorizationRule rule in rules)
                    {
                        FileSystemAccessRule fsAccessRule = rule as FileSystemAccessRule;
                        if (fsAccessRule == null)
                            continue;

                        if ((fsAccessRule.FileSystemRights & FileSystemRights.WriteData) > 0)
                        {
                            NTAccount ntAccount = rule.IdentityReference as NTAccount;
                            if (ntAccount == null)
                            {
                                continue;
                            }

                            if (principal.IsInRole(ntAccount.Value))
                            {
                                Console.WriteLine(dir);
                                continue;
                            }
                        }
                    }
                }
                catch (UnauthorizedAccessException)
                {
                }
                catch(InvalidOperationException)
                {
                }


                //Check if exists
                //If exists, try{ write to file }catch {not vulnerable} finally{remove folder}
                //If not exists try {create folder}catch {not vulnerable} finally{remove folder}

            }


        }
        static void checkUnattended()
        {
            Console.WriteLine("===============================================================================");
            Console.WriteLine("Searching for unattended.xml files.");
            Console.WriteLine("===============================================================================");
            String windowsPath = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            String[] searchlocations = { @"c:\sysprep\sysprep.xml", @"c:\sysprep\sysprep.inf", @"c:\sysprep.inf", windowsPath + @"\Panther\Unattended.xml", windowsPath + @"\Panther\Unattend\Unattended.xml", windowsPath + @"\Panther\Unattend.xml", windowsPath + @"\Panther\Unattend\Unattend.xml", windowsPath + @"\System32\Sysprep\unattend.xml", windowsPath + @"\System32\Sysprep\Panther\unattend.xml" };

            foreach(String file in searchlocations)
            {
                if (File.Exists(file))
                {
                    Console.WriteLine("Found unattended file at " + file);
                    string text = System.IO.File.ReadAllText(file);
                    Console.WriteLine(text);
                }
            }
        }
        static void checkServicePrivEsc()
        {



            //Enumerate common privilege escalation vectors.
            //Check for unquoted Service Paths
            //Check for modifiable service files
            //Check for modifiable service


        }

        static void checkTwoFactor()
        {

            Console.WriteLine("===============================================================================");
            Console.WriteLine("Checking to see if Two Factor is enabled");
            Console.WriteLine("===============================================================================");
            //This calls an x64 Registry Hive, this may need to be modified for 32-bit systems. It has not been tested yet.
            string[] arrTwoFactorKeys = new string[5] { @"HKEY_LOCAL_MACHINE\SOFTWARE\Duo Security\DuoCredProv", @"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Duo Security\DuoCredProv", @"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider", @"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CertProp", @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Ginadll"};
            //Duo Check
            //HKEY_LOCAL_MACHINE\SOFTWARE\Duo Security\DuoCredProv When installed through Installer.
            //HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Duo Security\DuoCredProv When installed with GPO.
            

            foreach (string key in arrTwoFactorKeys) {
                using (RegistryKey basekey = Registry.LocalMachine.OpenSubKey(key))
                    if (basekey != null)
                    {
                    Console.WriteLine("Two Factor Enabled on LocalMachine: \n" + key + " Found");
                    }
                    else
                    {
                    Console.WriteLine(key + " not found");
                    }
            }

            //Check for DUO
            //HKEY_LOCAL_MACHINE\SOFTWARE\Duo Security\DuoCredProv When installed through Installer.
            //HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Duo Security\DuoCredProv When installed with GPO.
            //Secret Key is protected from low priv users however, so need to check for other indicators possibly. (Maybe just check if exists will bypass this)
            //Check for Smart Cards
            //HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider
            //HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CertProp
            //Check for Google 2FA
            //RSA Token
            //HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Ginadll
            //Need to check what GINAis being used (default is msgina.dll)

        }
        static void checkLogging()
        {
            Console.WriteLine("===============================================================================");
            Console.WriteLine("Checking for PowerShell Logging...");
            Console.WriteLine("===============================================================================");
            //This calls an x64 Registry Hive, this may need to be modified for 32-bit systems. It has not been tested yet.
            using (var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
            using (var key = hklm.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\Powershell\"))
            {
                foreach (string localkey in key.GetSubKeyNames())
                {
                    switch (localkey)
                    {
                        case "ModuleLogging":
                            Console.WriteLine("ModuleLogging is enabled.");
                            break;
                        case "ScriptBlockLogging":
                            Console.WriteLine("ScriptBlockLogging is enabled.");
                            break;
                        case "Transcription":
                            Console.WriteLine("Transcription is enabled.");
                            break;
                    }
                }
            }
        }
        static void checkEventForwarding()
        {
            //Console.WriteLine("===============================================================================");
            //Console.WriteLine("Checking for Windows Event Forwarding...");
            //Console.WriteLine("===============================================================================");
        }



        static void getRDPSessions()
        {
            Console.WriteLine("===============================================================================");
            Console.WriteLine("Getting RDP Sessions...");
            Console.WriteLine("===============================================================================");
            IntPtr pServer = IntPtr.Zero;
            string sUserName = string.Empty;
            string sDomain = string.Empty;
            string sClientApplicationDirectory = string.Empty;
            string sIPAddress = string.Empty;
            WTS_CLIENT_ADDRESS oClientAddres = new WTS_CLIENT_ADDRESS();
            IntPtr pSessionInfo = IntPtr.Zero;
            int iCount = 0;
            int iReturnValue = WTSEnumerateSessions(pServer, 0, 1, ref pSessionInfo, ref iCount);
            int iDataSize = Marshal.SizeOf(typeof(WTS_SESSION_INFO));
            int iCurrent = (int)pSessionInfo;
            if (iReturnValue != 0)
            {
                //Go to all sessions
                for (int i = 0; i < iCount; i++)
                {
                    WTS_SESSION_INFO oSessionInfo = (WTS_SESSION_INFO)Marshal.PtrToStructure((System.IntPtr)iCurrent,
                typeof(WTS_SESSION_INFO));
                    iCurrent += iDataSize;

                    uint iReturned = 0;

                    //Get the IP address of the Terminal Services User
                    IntPtr pAddress = IntPtr.Zero;
                    if (WTSQuerySessionInformation(pServer, oSessionInfo.iSessionID, WTS_INFO_CLASS.WTSClientAddress, out pAddress, out iReturned) == true)
                    {
                        oClientAddres = (WTS_CLIENT_ADDRESS)Marshal.PtrToStructure(pAddress, oClientAddres.GetType());
                        sIPAddress = oClientAddres.bAddress[2] + "." + oClientAddres.bAddress[3] + "." + oClientAddres.bAddress[4] + "." + oClientAddres.bAddress[5];
                    }
                    //Get the User Name of the Terminal Services User
                    if (WTSQuerySessionInformation(pServer, oSessionInfo.iSessionID, WTS_INFO_CLASS.WTSUserName,
                out pAddress, out iReturned) == true)
                    {
                        sUserName = Marshal.PtrToStringAnsi(pAddress);
                    }
                    //Get the Domain Name of the Terminal Services User
                    if (WTSQuerySessionInformation(pServer, oSessionInfo.iSessionID, WTS_INFO_CLASS.WTSDomainName,
                out pAddress, out iReturned) == true)
                    {
                        sDomain = Marshal.PtrToStringAnsi(pAddress);
                    }
                    //Get the Application Directory of the Terminal Services User
                    if (WTSQuerySessionInformation(pServer, oSessionInfo.iSessionID, WTS_INFO_CLASS.WTSClientDirectory, out pAddress, out iReturned) == true)
                    {
                        sClientApplicationDirectory = Marshal.PtrToStringAnsi(pAddress);
                    }
                    Console.WriteLine("Session ID : " + oSessionInfo.iSessionID);
                    Console.WriteLine("Session State : " + oSessionInfo.oState);
                    Console.WriteLine("Workstation Name : " + oSessionInfo.sWinsWorkstationName);
                    Console.WriteLine("IP Address : " + sIPAddress);
                    Console.WriteLine("User Name : " + sDomain + @"\" + sUserName);
                    Console.WriteLine("Client Application Directory: " + sClientApplicationDirectory);
                    Console.WriteLine("-----------------------");
                }
                WTSFreeMemory(pSessionInfo);
            }

        }

        static void getUptime()
        {
            Console.WriteLine("===============================================================================");
            Console.WriteLine("Getting Uptime...");
            Console.WriteLine("===============================================================================");
            using (var uptime = new PerformanceCounter("System", "System Up Time"))
            {
                uptime.NextValue();       //Call this an extra time before reading its value
                Console.WriteLine(TimeSpan.FromSeconds(uptime.NextValue()));
            }
        }

        static void getBlueTeam()
        {
            Console.WriteLine("===============================================================================");
            Console.WriteLine("Getting Blue Team Products...");
            Console.WriteLine("===============================================================================");
            Dictionary<string, string> secProducts = new Dictionary<string, string> {
                { "a2adguard", "a-squared emsisoft" },
                { "a2adwizard", "a-squared emsisoft" },
                { "a2antidialer", "a-squared emsisoft" },
                { "a2cfg", "a-squared emsisoft" },
                { "a2cmd", "a-squared emsisoft" },
                { "a2free", "a-squared emsisoft" },
                { "a2guard", "a-squared emsisoft" },
                { "a2hijackfree", "a-squared emsisoft" },
                { "a2scan", "a-squared emsisoft" },
                { "a2service", "a-squared emsisoft" },
                { "a2start", "a-squared emsisoft" },
                { "a2sys", "a-squared emsisoft" },
                { "a2upd", "a-squared emsisoft" },
                { "aavgapi", "avg security toolbar" },
                { "aawservice", "ad-aware" },
                { "aawtray", "ad-aware" },
                { "ad-aware", "ad-aware" },
                { "ad-watch", "ad-aware" },
                { "alescan", "norton personal firewall" },
                { "anvir", "anvir task manager" },
                { "ashdisp", "avast!" },
                { "ashmaisv", "avast!" },
                { "ashserv", "avast!" },
                { "ashwebsv", "avast!" },
                { "aswupdsv", "avast!" },
                { "atrack", "norton alert tracker" },
                { "avastui", "avast!" },
                { "avgagent", "avg" },
                { "avgamsvr", "avg" },
                { "avgcc", "avg" },
                { "avgctrl", "avg" },
                { "avgemc", "avg" },
                { "avgnt", "avg" },
                { "avgtcpsv", "avg" },
                { "avguard", "avira" },
                { "avgupsvc", "avg" },
                { "avgw", "avg" },
                { "avkbar", "g data avk" },
                { "avk", "g data avk" },
                { "avkpop", "g data avk" },
                { "avkproxy", "g data avk" },
                { "avkservice", "g data avk" },
                { "avktray", "g data avk" },
                { "avkwctl", "g data avk" },
                { "avmailc", "avira" },
                { "avp", "kaspersky" },
                { "avpm", "kaspersky" },
                { "avpmwrap", "kaspersky" },
                { "avsched32", "h+bedv" },
                { "avwebgrd", "avira" },
                { "avwin", "h+bedv" },
                { "avwupsrv", "h+bedv" },
                { "avz", "defender pro av" },
                { "bdagent", "bitdefender" },
                { "bdmcon", "bitdefender" },
                { "bdnagent", "bitdefender" },
                { "bdss", "bitdefender" },
                { "bdswitch", "bitdefender" },
                { "blackd", "blackice" },
                { "blackice", "blackice" },
                { "blink", "blink eeye digital security" },
                { "boc412", "comodo/boclean" },
                { "boc425", "comodo/boclean" },
                { "bocore", "comodo/boclean" },
                { "bootwarn", "norton antivirus" },
                { "cavrid", "ca antivirus" },
                { "cavtray", "ca antivirus" },
                { "ccapp", "norton antivirus" },
                { "ccevtmgr", "norton antivirus" },
                { "ccimscan", "norton antivirus" },
                { "ccproxy", "norton proxy" },
                { "ccpwdsvc", "norton internet security" },
                { "ccpxysvc", "norton internet security" },
                { "ccsetmgr", "norton antivirus" },
                { "cfgwiz", "norton internet security" },
                { "cfp", "comodo firewall" },
                { "clamd", "clamav" },
                { "clamservice", "clamav" },
                { "clamtray", "clamwin antivirus" },
                { "cmdagent", "comodo is" },
                { "cpd", "mcafee personal firewall" },
                { "cpf", "comodo firewall" },
                { "csinsmnt", "norton cleansweep" },
                { "dcsuserprot", "diamondcs/process guard" },
                { "defensewall", "defensewall/softsphere" },
                { "defensewall_serv", "defensewall/softsphere" },
                { "defwatch", "norton antivirus" },
                { "f-agnt95", "f-secure" },
                { "fpavupdm", "f-prot" },
                { "f-prot95", "f-prot" },
                { "f-prot", "f-prot" },
                { "fprot", "f-prot" },
                { "fsaua", "f-secure" },
                { "fsav32", "f-secure" },
                { "f-sched", "f-prot" },
                { "fsdfwd", "f-secure" },
                { "fsm32", "f-secure" },
                { "fsma32", "f-secure" },
                { "fssm32", "f-secure" },
                { "f-stopw", "f-prot" },
                { "fwservice", "pc tools" },
                { "fwsrv", "jetico firewall" },
                { "iamstats", "norton is" },
                { "iao", "norton is" },
                { "icload95", "sophos" },
                { "icmon", "sophos" },
                { "idsinst", "symantec ids" },
                { "idslu", "symantec" },
                { "inetupd", "h-bedv" },
                { "isafe", "ca antivirus" },
                { "issvc", "norton iss" },
                { "kav", "kaspersky antivirus" },
                { "kavss", "kaspersky antivirus" },
                { "kavsvc", "kaspersky antivirus" },
                { "klswd", "kaspersky antivirus" },
                { "kpf4gui", "kerio personal firewall" },
                { "kpf4ss", "kerio personal firewall" },
                { "livesrv", "bitdefender" },
                { "lpfw", "lavasoft personal firewall" },
                { "mbam", "MalwareBytes" },
                { "mcagent", "mcafee security center" },
                { "mcdetect", "mcafee security center" },
                { "mcmnhdlr", "mcafee virus scan" },
                { "mcshield", "mcafee on-access" },
                { "mctskshd", "mcafee task scheduler" },
                { "mcvsshld", "mcafee virus scan" },
                { "mghtml", "mcafee virus scan" },
                { "mpftray", "mcafee internet security" },
                { "msascui", "windows defender anti-spyware" },
                { "msascuil", "Windows Defender" },
                { "mscifapp", "mcafee privacy service" },
                { "msfwsvc", "microsoft onecare firewall" },
                { "msgsys", "landesks aws" },
                { "msssrv", "mcafee antispyware" },
                { "navapsvc", "norton antivirus" },
                { "navapw32", "norton av auto protect" },
                { "navlogon.dll", "norton antivirus" },
                { "navstub", "norton antivirus" },
                { "navw32", "norton antivirus" },
                { "nisemsvr", "norton internet security" },
                { "nisum", "norton internet security" },
                { "nmain", "norton antivirus" },
                { "noads", "noads popup blocker" },
                { "nod32krn", "nod32 antivirus" },
                { "nod32kui", "nod32 antivirus" },
                { "nod32ra", "nod32 antivirus" },
                { "npfmntor", "norton antivirus" },
                { "nprotect", "norton protection" },
                { "nsmdtr", "norton antivirus" },
                { "oasclnt", "mcafee internet security" },
                { "ofcdog", "trend micro" },
                { "opscan", "norton antivirus" },
                { "ossec-agent", "ossec hids" },
                { "outpost", "agnitum outpost firewall" },
                { "paamsrv", "acronis pam" },
                { "pavfnsvr", "panda titanium antivirus" },
                { "pcclient", "trend micro" },
                { "pccpfw", "trend micro firewall" },
                { "persfw", "kerio/tiny personal firewall" },
                { "qconsole", "norton antivirus" },
                { "qdcsfs", "norton cleansweep" },
                { "rtvscan", "symantec endpoint protection" },
                { "sadblock", "adblock" },
                { "sandboxieserver", "sandboxie service" },
                { "savscan", "norton antivirus" },
                { "sbiectrl", "sandboxie service" },
                { "sbiesvc", "sandboxie service" },
                { "sbserv", "scriptblocking" },
                { "scfservice", "sophos client firewall" },
                { "sched", "avira scheduler" },
                { "sdhelp", "spyware doctor" },
                { "sgbhp", "spywareguard" },
                { "sgmain", "spywareguard" },
                { "slee503", "steganos security suite" },
                { "smartfix", "defendgate smartfix security" },
                { "smc", "sygate agent firewall" },
                { "snoopfreesvc", "snoopfree privacy shield" },
                { "snoopfreeui", "snoopfree privacy shield" },
                { "spbbcsvc", "symantec internet security" },
                { "sp_rsser", "spyware terminator" },
                { "spyblocker", "spyblocker" },
                { "spybotsd", "spybot s&d" },
                { "spysweeper", "webroot spysweeper" },
                { "spysweeperui", "webroot spysweeper" },
                { "spywareguard.dll", "spyware guard" },
                { "spywareterminatorshield", "spyware terminator" },
                { "ssu", "webroot spysweeper" },
                { "steganos5", "steganos security suite" },
                { "stinger", "mcafee stinger" },
                { "swdoctor", "spyware doctor" },
                { "swupdate", "sophos antivirus" },
                { "symlcsvc", "norton internet security" },
                { "symundo", "norton shared component" },
                { "symwsc", "norton internet security" },
                { "symwscno", "norton security center" },
                { "tds-3", "diamondcs" },
                { "teatimer", "spybot s&d" },
                { "tgbbob", "sistech/thegreenbow" },
                { "tgbstarter", "sistech/thegreenbow" },
                { "tsatudt", "omniquad total security" },
                { "umxagent", "ca hips" },
                { "umxcfg", "ca hips" },
                { "umxfwhlp", "ca hips" },
                { "umxlu", "etrust firewall" },
                { "umxpol", "ca hips" },
                { "umxtray", "tiny firewall" },
                { "usrprmpt", "norton security center" },
                { "vetmsg9x", "ca antivirus" },
                { "vetmsg", "ca antivirus" },
                { "vptray", "norton antivirus" },
                { "vsserv", "bitdefender" },
                { "wcantispy", "wincleaner antispyware" },
                { "winpatrol", "winpatrol monitor" },
                { "winpatrolex", "winpatrol explorer" },
                { "wrsssdk", "webroot spysweeper" },
                { "xcommsvr", "bitdefender" },
                { "xfr", "symantec system center" },
                { "xp-antispy", "xp-antispy" },
                { "zlclient", "zonelabs firewall" } };
            //Console.WriteLine(secProducts["a2adguard.exe"]);
            //Get list of running processes
            //Check that for the list of running executables.
            Process[] allProcesses = Process.GetProcesses();
            foreach (Process processName in allProcesses) {
                if (secProducts.ContainsKey(processName.ProcessName.ToString().ToLower()))
                {
                    Console.WriteLine("Blue Team Product Found:");
                    Console.WriteLine(secProducts[processName.ProcessName.ToString().ToLower()]);
                }
                //Console.WriteLine(processName.Id + " " + processName.ProcessName);
            }
        }
        static void getLocalGroups()
        {
            Console.WriteLine("===============================================================================");
            Console.WriteLine("Getting Local Groups");
            Console.WriteLine("===============================================================================");
            List<String> groups = new List<string>();
            DirectoryEntry machine = new DirectoryEntry("WinNT://" + Environment.MachineName + ",Computer");
            foreach (DirectoryEntry child in machine.Children)
            {
                if (child.SchemaClassName == "Group")
                {
                    groups.Add(child.Name.ToString());
                }
            }
            groups.ForEach(delegate (String groupName) {
                Console.WriteLine("-------------------------------------------------------------------------------");
                Console.WriteLine(groupName);
                Console.WriteLine("-------------------------------------------------------------------------------");
                GetMembers(groupName);
                Console.WriteLine("\n");
            });
        }
        //Get members of local groups function, returns of list of users in each group and outputs to console.
        static void GetMembers(string GroupName)
        {
            List<string> lstUsers = new List<string>();
            DirectoryEntry localmachine = new DirectoryEntry("WinNT://" + Environment.MachineName);
            DirectoryEntry group = localmachine.Children.Find(GroupName, "group");
            object members = group.Invoke("members", null);
            foreach (object groupMember in (IEnumerable)members)
            {
                DirectoryEntry member = new DirectoryEntry(groupMember);
                Console.WriteLine(member.Name.ToString());
                lstUsers.Add(member.Name);
            }
            if (lstUsers.Count == 0)
            {
                Console.WriteLine("No members of the " + GroupName + " group Found");
            }
        }

        static void getADMembership()
        {
            Console.WriteLine("===============================================================================");
            Console.WriteLine("Getting AD Memberships...");
            Console.WriteLine("===============================================================================");
            //Todo: Get Current Users AD Memberships?
            //Not connected to AD right now, needs to be tested.
            //Https://stackoverflow.com/questions/5309988/how-to-get-the-groups-of-a-user-in-active-directory-c-asp-net/
            List<GroupPrincipal> results = new List<GroupPrincipal>();
            PrincipalContext pc = new PrincipalContext(ContextType.Domain);
            UserPrincipal currentUser = UserPrincipal.Current;

            if (currentUser != null)
            {
                PrincipalSearchResult<Principal> groups = currentUser.GetAuthorizationGroups();

                foreach (Principal p in groups)
                {
                    if (p is GroupPrincipal)
                    {
                        Console.WriteLine(p);
                    }
                }
            }
        }

        static void getDirectoryListing(string folder)
        {
            //To Do
            try
            {
                foreach (string f in Directory.GetFiles(folder))
                {
                    //Regex r = new Regex("txt|docx|web.config");
                    Regex r = new Regex("web\\.config$");
                    bool containsAny = r.IsMatch(f);
                    if (containsAny == true)
                    {
                        Console.WriteLine(f);
                    }

                }
                foreach (string d in Directory.GetDirectories(folder))
                {
                   // Console.WriteLine(d);
                    getDirectoryListing(d);
                }

            }
            catch (System.Exception ex)
            {
            }
        }

        static void getFirewall()
        {
            Console.WriteLine("===============================================================================");
            Console.WriteLine("Getting Windows Firewall Rules...");
            Console.WriteLine("===============================================================================");
            INetFwPolicy2 fwPolicy2 = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
            List<INetFwRule> RuleList = new List<INetFwRule>();
            List<string> PortsList = new List<string>();
            foreach (INetFwRule rule in fwPolicy2.Rules)
            {
                RuleList.Add(rule);
                if (rule.RemotePorts != null && rule.RemotePorts != "*")
                {
                    //PortsList.Add(rule.RemotePorts);
                    //Console.WriteLine(rule.RemotePorts + " Allowed outbound");
                    PortsList.Add(rule.RemotePorts);
                }
            }
            List<string> result = PortsList.Select(o => o).Distinct().ToList();
            result.Sort();

            foreach(string port in result)
            {
                Console.WriteLine(port);
            }

            //Console.WriteLine(RuleList[200].Name);
            //Console.WriteLine(RuleList[200].LocalPorts);
            //Console.WriteLine(RuleList[200].serviceName);
            //Console.WriteLine(RuleList[200].Protocol);
            //Console.WriteLine(RuleList[200].Enabled);

        }

        static void deleteSelf()
        {

        }

        static void getInstalledApplications()
        {
            Console.WriteLine("===============================================================================");
            Console.WriteLine("Enumerating Installed Applications...");
            Console.WriteLine("===============================================================================");
            //http://stackoverflow.com/questions/908850/get-installed-applications-in-a-system/
            List<string> lstDisplayName = new List<string>();
            List<string> lstVersion = new List<string>();
            string strRegKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
            Console.WriteLine("Application Name" + "\t\t\t\t\t" + "Application Version");
            Console.WriteLine("-------------------------------------------------------------------------------");
            using (Microsoft.Win32.RegistryKey key = Registry.LocalMachine.OpenSubKey(strRegKey))
            {
            foreach(string subkey_name in key.GetSubKeyNames())
            {
                    using (RegistryKey subkey = key.OpenSubKey(subkey_name))
                    {
                        if (subkey.GetValue("DisplayName") != null)
                        {
                            string strAppName = subkey.GetValue("DisplayName").ToString();
                            string strShort;
                            strShort = strAppName.Substring(0, Math.Min(50, strAppName.Length));
                            strShort = strShort.PadRight(60, '-');

                            Console.WriteLine(strShort + "" + subkey.GetValue("DisplayVersion"));
                        }
                    }
            }
            }
        }

        public void searchFiles()
        {

        }
        static void getShares()
        {
            Console.WriteLine("===============================================================================");
            Console.WriteLine("Getting Local Shares...");
            Console.WriteLine("===============================================================================");
            Dictionary<string, string> shares = new Dictionary<string, string>();
            string serverName = Environment.MachineName;
            using (RegistryKey reg = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, serverName))
            {
                using (RegistryKey key = reg.OpenSubKey(@"SYSTEM\CurrentControlSet\services\LanmanServer\Shares"))
                {
                    foreach (string shareName in key.GetValueNames())
                    {
                        // Network share local path
                        List<string> keyValues = ((string[])key.GetValue(shareName)).ToList();
                        string shareLocalPath = keyValues.Where(a => a.StartsWith("Path=")).FirstOrDefault().Substring(5);
                        Console.WriteLine("Name: " + shareName + "\r\n  Path: " + shareLocalPath + "\r\n-----------------------");
                    }
                }
            }
        }

        static void getOSVersion()
        {
            Console.WriteLine("===============================================================================");
            Console.WriteLine("Getting OS Version...");
            Console.WriteLine("===============================================================================");
            Console.WriteLine(Environment.OSVersion.ToString());
            string strRegKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\";
            using (Microsoft.Win32.RegistryKey key = Registry.LocalMachine.OpenSubKey(strRegKey))
            {
                Console.WriteLine(key.GetValue("ProductName"));
                if(key.GetValue("CSDVersion") != null)
                {
                Console.WriteLine(key.GetValue("CSDVersion"));
                }
                if (key.GetValue("BuildLabEx") != null)
                {
                    Console.WriteLine(key.GetValue("BuildLabEx"));
                }
            }
        }

        public void getMostUsedApps()
        {

        }

        static void getClipboard()
        {
            Console.WriteLine("===============================================================================");
            Console.WriteLine("Getting Clipboard Content...");
            Console.WriteLine("===============================================================================");
            if (Clipboard.ContainsText(TextDataFormat.Text))
            {
                Console.WriteLine(Clipboard.GetText(TextDataFormat.Text));
            }
            else
            {
                Console.WriteLine("No text on the clipboard right now :(");
            }
        }
    }
}
