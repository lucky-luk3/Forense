# Windows
## Misc
[tool] SysINternals - Handle, show us wich process are using some file.  
`PS>Get-ChildItem -Hidden C:\ -Recurse -ErrorAction SilentlyContinue | Select-Object Name,CreationTime,LastAccessTime,LastWriteTime | Export-Csv -NoTypeInformation fichero.csv`  &rarr; create a csv with files and some data  
Use `\\?\` after path to access to a raw file. 
`icacls.exe \\?\C:\Users\user1\Desktop\keys` &rarr; show you a acls of this file..  

## USRJRNL (user journal)
File in C:\$Extend\$J
```
.\MFTECmd.exe -f "C:\Users\test\Documents\test\collected\2021-04-04T171913_BUDB06\C\$Extend\$J" --csv "C:\Users\test\Documents"
```


## Recycle Bin
### Windows 10
* [tool] Rifiuti (FoundStone)
* CMD `dir C:\$Recycle.Bin /a` &rarr; SID (Security Identificator)
    *  S-1-5-21-3188859672-1871729041-1547734134-1000
        * S-1-5-21  &rarr; Windows common
        * 3188859672-1871729041-1547734134 &rarr; User Privileges
        * 1000 &rarr; User Identificator. 500 = Administrator. Could compare admin privileges with other users
            * [tool] Sysinternals - psgetsid -  translate between SID and username
            * For each file here are 2 files
                * One that starts with I (INODE) and its a pointer to a original path. `type C:\$Recycle.Bin\SID\$IJHGDJH.exe`.
                * Other that starts with R (RECURSE) that is the complet file.
                * If $I* file doesn't exist, the user don't see this file in the app windows, even if the $R* file exist.
                
## Prefetching `C:\Windows\Prefech`
Superfetch it's a service running in windows that keep some information in **client** versions of windows. IN servers are disableb by default.  
When you start an app, the OS monitorize the file load and create a file with the path of application, dlls in the OS and pointers in de HD of this application.  
When you start an app the OS read this file first.  
Its useful to know if some app or file was open in the computer.  
* [tool] Nirsoft - WinPrefetchView.
* [tool] Prefetch Info - Mark McKinnon.
* Info in the prefetch files:
    * Path of dlls (research about mofified prefetch files for to do a dll hijack).
    * Path of exe .
    * First execution (creation time).
    * Last execution (modified time).
    * Counter of executions.
    * In some applications you can see files opened with this app.
* Prefetch don't be able to determine wich user used this app.
* Every 72 hours it makes a inventory of apps most used.
* Layout.ini &rarr; it's information that the OS precharge in memory at the beggining of your session. (is it possible to infect it?).
* Even if you have dissable Superfetch service, you can launch an app with prefetch enable:
    * `%systemroot%\system32\notepad.exe /prefetch:1` &rarr; you can create a shorcut with this command. (command not valid).

## Shadow Copy
Copies that the system does when some file it's modified or some critial action are running in the computer. Differencial backup.
Service `Volume Shadow Copy`.  
It's possible to do a dd copy from a shadowcopy.
In Windows 8 Prvius Version are hidden.
* [tool] Sysinternals - WinObj &rarr; GLOBAL?? HarddiskVolumeShadowCopy  
* [tool] Windows - vssadmin &rarr; `list shadows`, `delete shadows`... manage shadow copies.  
`File &rarr; Options &rarr; Previus Version &rarr; File system`  
Configuration: `Computer &rarr; Manage/Properties &rarr; Advance settings &rarr; System Protection &rarr; Configure`  
Only 'System' can read this information, it's hidden:
* `AdminCMD>psexec -i -s cmd.exe`
    * `SystemCMD>cd "C:\System Volume Information"`
```
$s1 = (gwm1 -List Win32_ShadowCopy).Create("C:\", "ClientAccessible")
$s2 = gwmi Win32_ShadowCopy | ? { $_.ID -eq $s1.ShadowID}
$d = $s2.DeviceObject + "\"
cmd /c mklink /d C:\shadowcopy "$d"
```
Are a registry key that is a black list, files or folders there are not saved.  
`SYSTEM\CurrentControlSet\BackupRestore\FilesNotToBackup`  
Mount shadowcopy:
* `mklink /d c:\shadow \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy3\` Importan the last \.
* `net share shadow=\\.\Harddisk\VolumeShadowCopy3\` &rarr; Share shadow copy to network.
* In explorer `\\localhost\C$\@GMT-2020.01.10-13.29.43`  

## Internet Explorer
* [tool] Nirsoft
* [tool] Nirsoft - BrowsingHistoryView
Cache Win7 &rarr; `C:\User\user1\AppData\Local\Microsoft\Windows\INetCache\`  
Cache Win7 &rarr; `C:\User\user1\AppData\Local\Microsoft\Temporary internet Files\`  
IExplorer from PS `$ie = New-Object -ComObject InternetExplorer.Application`  

## Mozilla
* [tool] Mozilla - SQLiteManager
* [tool] Nirsoft
* `~\AppData\Roaming\Mozilla\Firefox\Profiles`
    * cookies.sqlite
    * formhistory.sqlite
    * places.sqlite  &rarr; history
    * signons.sqlite  &rarr; passwords

## Chrome
* [tool] Mozilla - SQLiteManager
* [tool] Nirsoft
* `~\AppData\Local\Google\Chrome\User Data\Default`
    * cookies
    * history  &rarr; history
    * Login data
    * Last session
    * Current session
    * Bookmarks
    
## Pagefile
When memory is full of data, the OS create pagefile and use it like memory.  
`strings pagefile.sys > strings_pag.txt`  
`findstr /I url strings_pag.txt`

## Event Analysis
We could change group policy in order to log more information.  
Computer configuration/Windows Settings/Security Settings/Local Policies/Audit Policy/  
Files stored in: `C:\Windows\System32\winevt\Logs`  
[tool] LogParser - SQL sintaxis - offline - local or remote - called like a COM object - python
```
>logparser.exe -h -i:EVT &rarr; show info about this format and what fields it's possible to ask about.  
>LogParser "SELECT EventID FROM C:\Users\luisf\Documents\Security.evtx " -i:EVT  
>LogParser "SELECT EventID,Message,COmputerName FROM C:\Users\luisf\Documents\Security.evtx " -i:EVT -o:DATAGRID  
>LogParser "SELECT EventID,Message,COmputerName INTO fichero.XML FROM C:\Users\luisf\Documents\Security.evtx " -i:EVT -o:xml  
>LogParser file:W9Logon.sql   &rarr; execute this sentence  
```
[tool] Evtx Explorer - GUI - Powerfull filters
[tool] Powershell - Script log.ps1 - helps to extract info from event files.
```PS
>.\Logs.ps1 -Path  .\System.evtx -StartDays 15 -EventID 7045 -message PSEXEC | Format-List
>Get-WinEvent
>LogParser file:W8Logon.sql
```

### Events most used
#### Security
* 4624 &rarr; Logon.
* 4625 &rarr; Failed logon.
* 4634 &rarr; Logoff.
* 4649 &rarr; A replay attack was detected (smb attack using hash, old ).
* 4675 &rarr; SIDs were filteres, when you have a filter to some users and it tries to logon.
* 4778 &rarr; A session was reconnected to a Windows Station. 
* 4800 &rarr; waskstation was locked.
* 4801 &rarr; waskstation was unlocked.
* 4802 &rarr; screen saver was invoked.
* 4803 &rarr; screen saver was dismissed.
* 5632 &rarr; Request to authenticate to a wireless network.
* 5633 &rarr; Request to authenticate to a wired network.

#### Application
* 7045 &rarr; new service was installed in the system (windows server 2016?)
* 7035 and 7036 &rarr; PSExec events


### Logon types
* 2 &rarr; Interactive
* 10 &rarr; Remote Interactive
* 4 &rarr; Batch
* 5 &rarr; Service
* 7 &rarr; Unlock
* 8 &rarr; Network clear text
* 9 &rarr; New Credentials
* 11 &rarr; Cached Logon


## Windows Registry  
[tool] Zimmerman - Registry Explorer
[tool] RegRipper.  
[tool] Windows Registry Recovery.  
[tool] Autoruns - Sysinternals - Its possible to hide Microsoft entries.  
Copy with shadows copies or FTK  
* HKEY_CLASSES_ROOT (HKCR) &rarr; How must be executed an application --> (HKLM\Software\Clases)
* HKEY_CURRENT_USER (HKCU) &rarr; Profile of the user logged.
* HKEY_LOCAL_MACHINE (HKLM) &rarr; OS configuration.
* HKEY_USERS (HKU) &rarr; Profiles in the OS.
* HKEY_CURRENT_CONFIG (HKCC) &rarr; Hardware profiles.

* ntuser.dat &rarr; C:\Users\user1\ &rarr; Recently used files and user preferences
* Default &rarr; C:\Windows\system32\config &rarr;  System settings
* SAM  &rarr; C:\Windows\system32\config &rarr; User account management and security settings
* Security &rarr; C:\Windows\system32\config &rarr;  Security settings
* Software &rarr; C:\Windows\system32\config &rarr; All installed programs and their settings
* System &rarr; C:\Windows\system32\config &rarr; System settings


`>reg query HKLM\Software\Classes`  
`wmi `  &rarr; Look for
`PowerShell`

### Persistence entries
Userland:  
* HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
* HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce
Admin Privs:  
* HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
* HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
* HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
* HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
* HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce  

smss.exe  
* HKLM\SYSTEM\CurrentControlSet\Control\hivelist
* HKEY_LOCAL_MACHINE\SYSTEM\ControlSet002\Control\Session Manager

winlogon:  
* HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
Secure Attention Sequence (SAS) (Ctrl+Alt+Del)  
* HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify

Explorer.exe:  
* HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell
* HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\IniFileMapping\system.ini\boot

Startup Keys:  
* HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
* HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
* HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
* HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders

Services:  
* HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services

## Active directory Persistence
### Golden Ticket
When an attacker has krbtgt hash can create his own TGT for any user in the domain.  
It allows him to request to de DC for any TGS using the appropriated TGT.

### Silver Ticket
When the attacker has a hash for a service account, are able to create valid TGS for thi service.  
It's possible to do this with any user when you have a NTLM hash of the service.  
It's very useful because are not any interaction with the DC. In other hand, it's more common that 
the service password was changed than krbtgt one.  

### Skeleton Key
This technique patch a lsass process in the domain controller  and allows access as any user with a single password.  
This technique is not persistence across reboots.  

### DSRM (Directory Services Restore Mode)
When an attacker has privileged access to the DC, he can extract local password hashes from LSA.  
This technique uses the local administrator password, this password is used to promote a server to DC.  
This password is also called "SafeModePassword".  
By default this account is not able to login over the network. 
Ir order to be able to use it, it's necessary to change:  
* "HKLM:\System\CurrentControlSet\Control\Lsa\"
    * "DsrmAdminLogonBehavior" to "2" DWORD type.
    
### Custom SSP (Security Support Provider)
SSP is a dll that provides ways to obtain authenticated connections. (pe NTLM, Kerberos...)  
Mimikatz provides a custom SSP (mimilib.dll), it provides local logons, service account and machine account passwords in clear text on the target server.  
This technique allow to an attacker to obtain clear text passwords.  
It's necessary to change:  
* Put mimilib in system32 
* "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\" and "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\"
     * "SecurityPackages" add mimilib

It's also possible to inject this ddl in lsass process but maybe is unstable.   
It will generate a log file in "C:\Windows\System32\kiwissp.log"

### AdminSDHolder - ACLs
AdminSDHolder is an feature that try to protect "protected groups" for changes.  
Every 60 minutes, the ACLs from AdminSDHolder are applied to protected groups.  
If an attacker with elevated permissions modify AdminSDHolder ACLs, it's possible to modify also all the others sensitive groups.  
Protected Groups:  
* Account Operators (Cannot modify DA/EA/BA groups. Can modify nested group within these groups)
* Backup Operators (Backup GPO, edit to add SID of controlled account to a privileged group and Restore)
* Server Operators (Run commands as system)
* Print Operator (Copy ntds.dit backup, load device drivers)
* Domain Admin
* Replicator
* Enterprise Admins
* Domain Controllers
* Read-only Domain Controllers
* Schema Admins
* Administrators

### Rights Abuse - ACLs
It's possible to modify ACLs for root domain admin object, it provides to an attacker the possibility to run "DCSync"  
It is silent because the log level in this object is not so high.  
To perform DCSync it's possible to find full control in some user but also it is possible with 3 permissions:  
* Replicating Directory Changes
* Replicating Directory Changes All
* Replicating Directory Changes in Filtered Set

This user does not need to be in domain admin group.

### Security Descriptors - ACLs
It's possible to modify DACLs and SACLs for some object or service, in order to allow privileges only for a user.  
For example, DCOM, WMI and PowerShell Remote.

## Shimcache
[tool] Zimmerman - Registry Explorer
It records last execution time for apps. 
```
HKLM\SYSTEM\CurrentControlSet\Control\SessionManager\AppCompatCache\AppCompatCache
```

## File History
[tool] ESEDatabaseView - Nirsoft  
HKLM\System\CurrentControlSet\Services\fhsvc\Configs &rarr; C:\Users\user\AppData\Local\Microsoft\Windows\FileHistory\Configuration\Config &rarr; Catalog.edb and Config.xml
* UserFolder &rarr; Folder that will be saved
* FolderExclude &rarr;  Folder that will be skiped
* Target &rarr;  Destination of the information
`fsutil usn enumdata 1 0 1 C:` 

## WMI
You can search for the commands abailable to ask. Ejecute &rarr; WBEMTEST.  
Conect to a computer, Open Class, it's possible to search for a command and you can see the parameters and response.  
### Shortcut
* `Get-WmiObject -Class win32_shortcutfile -ComputerName . | Export-Csv C:\tmp\shortcut.csv` &rarr; You can search for opened files (user filter possible)

## Attacks profiling
* Meterpreter psexec
    * Login (event 4624, type remote, random source machine)
    * Create a service (event 7045) kill them
    * Close handle
    * Delete ".exe"
    * Create meterpreter in memory
* Pass the Hash
    * Users debug privilege
    * Audit object access group policy
    
## Memory Analysis
* Netstat &rarr; netscan
* Connections &rarr; connscan
* lsa secrets &rarr; lsadump
* Hashes NTLM &rarr; hashdump
* DNS cache
    * Identify host file &rarr; filescan | grep -i hosts
    * Dump file &rarr; dumpfiles -Q 0x2192f90 -D OUTDIR --name
    * Extract strings &rarr; strings OUTDIR/file.None.0x8211f1f8.hosts.dat
* Services &rarr; svcscan
* psxview &rarr; search for hidden process.
* dlllist &rarr; dll loaded
* ldrmodules &rarr; search for hidden dlls.
* malfind &rarr; find hidden dlls or injected in process.
* Last services created in volshell:
   This code shows created or modified services in last three timestamps. It's possible that this commnad shows more services than svcsacn, it could by because it's possible to create hidden services.
```python
 import volatility.plugins.registry.registryapi as registryapi
 regapi = registryapi.RegistryApi(self._config)
 key = "ControlSet001\Services"
 subkeys = regapi.reg_get_all_subkeys("system", key)
 services = dict((s.Name, int(s.LastWriteTime)) for s in subkeys)
 times = sorted(set(services.values()), reverse=True)
 top_three = times[0:3]
 for time in top_three:
   for name, ts in services.items():
      if ts == time:
         print time, name
```
* Print registry key &rarr; printkey -K 'ControlSet001\Services\HiddenService'
* Kernel modules &rarr; modules | grep bad.sys
* Clipboard data &rarr; clipboard
    * If file is copied to clipboard, not all document are in the clipboard, with -v option, it's possible to see the full path of the file.
* Master File Table &rarr; mftparser
    * for capture data streams it's necessary &rarr; --output-file=mftverbose.txt –D mftoutput
* Autoruns &rarr; Search for persistences. Necessary to install it https://github.com/tomchop/volatility-autoruns
   
##MFT (Master File Table)
```
# MFT to CSV
[zimmerman] .\MFTECmd.exe -f "C:\Users\test\test\collected\2021-04-04T171913_aaaa\C\$MFT" --body "C:\Users\test\Documents" --blf --bdl C:
# CSV to Timeline
[sleuthkit] perl mactime.pl -z UTC -y -d -b "C:\Users\test\Documents\20210405145110_MFTECmd_$MFT_Output.body" > "C:\Users\test\Documents\test.csv"
```
[tool] Zimmerman - Timeline Explorer

### Use cases
#### Domain connection
1. connscan. Shows PID of process and connection destination.
2. psscan.
3. yarascan -Y "domain". Search for domain in process.
4. handles -p PID -t Mutant. Search for mutex.
5. handles -p PID -t Mutant. Handles to files, search for dlls or binaries.
6. dlllist -p PID. Search for dlls.
7. ldrmodules -p PID. Search for hidden dlls. (grep)
8. dlldump -p PID -b 0x00010000 -D dump. Dump dlls.
