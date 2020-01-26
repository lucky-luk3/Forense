# Windows
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
* [tool] Sysinternals - WinObj &rarr; GLOBAL?? HarddiskVolumeShadowCopy
* [tool] Windows - vssadmin &rarr; `list shadows`, `delete shadows`... manage shadow copies.
`Options &rarr; Previus Version &rarr; File system`
Configuration: `Computer &rarr; Manage/Properties &rarr; Advance settings &rarr; System Protection &rarr; Configure`
Only 'System' can read this information:
* `AdminCMD>psexec -i -s cmd.exe`
    * `SystemCMD>cd "C:\System Volume Information"`

    

## WMI
You can search for the commands abailable to ask. Ejecute &rarr; WBEMTEST.
Conect to a computer, Open Class, it's possible to search for a command and you can see the parameters and response.
### Shortcut
* `Get-WmiObject -Class win32_shortcutfile -ComputerName . | Export-Csv C:\tmp\shortcut.csv` &rarr; You can search for opened files (user filter possible)
