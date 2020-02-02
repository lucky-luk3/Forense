# Windows
## Misc
[tool] SysINternals - Handle, show us wich process are using some file.  
`PS>Get-ChildItem -Hidden C:\ -Recurse -ErrorAction SilentlyContinue | Select-Object Name,CreationTime,LastAccessTime,LastWriteTime | Export-Csv -NoTypeInformation fichero.csv`  &rarr; create a csv with files and some data  
Use `\\?\` after path to access to a raw file. 
`icacls.exe \\?\C:\Users\user1\Desktop\keys` &rarr; show you a acls of this file..  


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
[tool] Evtx Explorer -
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


### Logon types
* 2 &rarr; Interactive
* 10 &rarr; Remote Interactive
* 4 &rarr; Batch
* 5 &rarr; Service
* 7 &rarr; Unlock
* 8 &rarr; Network clear text
* 9 &rarr; New Credentials
* 11 &rarr; Cached Logon

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
    
