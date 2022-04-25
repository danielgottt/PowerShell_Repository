<##############################################################################
.SYNOPSIS
    Draft script for use during host baseline, specifically win10 machines.
   
    Created by: 01000111

.DESCRIPTION
    
    The output folder will be created for you asking you for the hostname
    The commands creating the files are simple and can be edited by
    those without advanced scripting skills.  The files produced also
    can be compressed, copied, analyzed and compared without expensive
    forensics or analysis tools, such as Notepad++ or WinMerge.
    Script requires PowerShell 3.0, Windows 7, Server 2008, or later,
    and must be run with administrative privileges.  
    Most commands are built into PowerShell 3.0 and later, but some
    tools will need to be installed first in order to use them, such
    as AUTORUNSC.EXE (http://www.microsoft.com/sysinternals/) and
    SHA256DEEP.EXE (http://md5deep.sourceforge.net), which are not
    required, but very useful for snapshots.  Be aware, though, that
    producing thousands of file hashes may require a long time.  
    
.TRAIL_HEADS
    Pulling service info


#>############################################################################# 

$Title = '
___       ______       _________                           ________                   __________             
__ |     / /__(_)____________  /________      _________    ___  __ )_____ _______________  /__(_)___________ 
__ | /| / /__  /__  __ \  __  /_  __ \_ | /| / /_  ___/    __  __  |  __ `/_  ___/  _ \_  /__  /__  __ \  _ \
__ |/ |/ / _  / _  / / / /_/ / / /_/ /_ |/ |/ /_(__  )     _  /_/ // /_/ /_(__  )/  __/  / _  / _  / / /  __/
____/|__/  /_/  /_/ /_/\__,_/  \____/____/|__/ /____/      /_____/ \__,_/ /____/ \___//_/  /_/  /_/ /_/\___/                                                                                          
'
$Title

###############################################################################
#                    These variables do not need to be adjusted
###############################################################################

#SET DATE
$DATE_PATH = Get-Date -format "yyyy-MM-dd"
$DATE_FULL = Get-Date
$DATE_DAY = Get-Date -format "dd"
$ZULU_TIME = Get-Date -Format 'u'
$DATE_MONTH = Get-Date -format "MM"
$DATE_YEAR = Get-Date -format "yyyy"
$HOSTNAME = (Get-WmiObject Win32_BIOS).SerialNumber

###############################################################################
# 
# Set Adjustable Variables
#
###############################################################################
$SCANDIR = "C:\"
$USER = $env:USERNAME

Write-Host "You are Auditing '$HOSTNAME' on '$ZULU_TIME' as '$USER'"
#Creation of Script Working directory, All variables should be identified prior to this step
$dirName = "c:\temp\'$HOSTNAME'_{0}" -f (get-date).ToString("dd-MM-yyyy-hh-mm")
md $dirName
cd $dirName

Write-Host "Script is Running..."
###############################################################################
# 
# Now run whatever commands you wish to capture operational state data.
# Please add more commands and use additional tools too.
#
###############################################################################


# Computer System Enumeration
Get-CimInstance -ClassName Win32_ComputerSystem | Out-File Computer_System.txt
Get-WmiObject Win32_NetworkAdapterConfiguration | where { $_.IpAddress -like "$LocalSubnet" } | select -ExpandProperty MACAddress | select -First 1 | Out-File -Append Computer_System.txt
Get-CimInstance -ClassName Win32_BIOS | Out-File -Append Computer_System.txt

# Environment Variables
#dir env:\ | Out-File -Append Computer_System.txt


# Users (Identifies Local Users on a machine)
Get-LocalUser –name * | Select Name, Enabled, SID, LastLogon, PasswordLastSet | Out-File Local_Users.txt

# Groups
Get-CimInstance -ClassName Win32_Group | Out-File Account_Information.txt


# Group Members
Get-CimInstance -ClassName Win32_GroupUser | Out-File -Append Account_Information.txt


# Password And Lockout Policies
# net.exe accounts | Out-File Password-And-Lockout-Policies.xt


# Local Audit Policy
# auditpol.exe /get /category:* | Out-File Audit-Policy.txt

Write-Host "This may take a second"

# SECEDIT Security Policy Export
secedit.exe /export /cfg SecEdit-Security-Policy.txt | out-null 


# Shared Folders
Get-SmbShare | Out-File SMB_Shares.txt


# Networking Configuration
Get-NetAdapter -IncludeHidden | Out-File Network_Information.txt
Get-NetIPAddress | Out-File -Append Network_Information.txt
Get-NetTCPConnection -State Listen | Sort LocalPort | Out-File -Append Network_Information.txt
Get-NetUDPEndpoint | Sort LocalPort | Out-File -Append Network_Information.txt
Get-NetRoute | Out-File -Append Network_Information.txt
netstat.exe -n  | Out-File -Append Network_Information.txt
netsh.exe winsock show catalog | Out-File -Append Network_Information.txt
Get-DnsClientNrptPolicy -Effective | Out-File -Append Network_Information.txt


# Windows Firewall and IPSec 
Get-NetConnectionProfile | Out-File Firewall_Settings.txt
Get-NetFirewallProfile | Out-File -Append Firewall_Settings.txt
Get-NetFirewallRule | Out-File -Append Firewall_Settings.txt
Get-NetIPsecRule | Out-File -Append Firewall_Settings.txt
# netsh.exe advfirewall export Network-Firewall-Export.wfw | out-null 


# Processes
Get-CimInstance -Class Win32_Process | select-object ProcessName,ProcessId,parentProcessID,CreationDate,executablePath,CommandLine | Out-File Processes.txt

# Drivers
Get-CimInstance -ClassName Win32_SystemDriver | Out-File System_Drivers.txt

#Startup Commands
Get-WmiObject -Class Win32_StartupCommand | Select-Object Name,Command,Location,User | Out-File StartupCommands.txt

#All Scheduled Tasks
Get-ScheduledTask | Select-Object State,Source,TaskName,TaskPath,URI | Out-File ScheduledTasks.txt

# DirectX Diagnostics
# dxdiag.exe /whql:off /64bit /t dxdiag.txt 

#Pull Installed Products
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object Publisher,DisplayName,DisplayVersion,InstallDate,InstallLocation,InstallSource | where Displayname -ne $NULL | Out-File Win32b_PROD.txt
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object Publisher,DisplayName,DisplayVersion,InstallDate,InstallLocation,InstallSource | where Displayname -ne $NULL | Out-File Win64b_PROD.txt

# Services
Get-Service | Sort-Object Status | Format-List -Property Status, Name, DisplayName,ServiceType | Out-File Stopped-Started_Services.txt


# Registry Exports (add more as you wish)
Get-ItemProperty?HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\* | Format-Table –Property FriendlyName, ContainerID | Out-File Registry_Baseline.txt
Get-ItemProperty?HKLM:\Software\Microsoft\Windows\CurrentVersion\Run\? | Out-File -Append Registry_Baseline.txt
Get-ItemProperty?HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce\? | Out-File -Append Registry_Baseline.txt
Get-ItemProperty?HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce\? | Out-File -Append Registry_Baseline.txt 
Get-ItemProperty?HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\? | Out-File -Append Registry_Baseline.txt

Get-ItemProperty?'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders\' | Out-File Persistence_Reg_Baseline.txt
Get-ItemProperty?'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\' | Out-File -Append Persistence_Reg_Baseline.txt
Get-ItemProperty?'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' | Out-File -Append Persistence_Reg_Baseline.txt
Get-ItemProperty?'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' | Out-File -Append Persistence_Reg_Baseline.txt

Get-ItemProperty?HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce\ -ErrorAction SilentlyContinue | Out-File Service_Control_HKEY_Baseline.txt 
Get-ItemProperty?HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce\ -ErrorAction SilentlyContinue? | Out-File -Append Service_Control_HKEY_Baseline.txt
Get-ItemProperty?HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices\? -ErrorAction SilentlyContinue | Out-File -Append Service_Control_HKEY_Baseline.txt
Get-ItemProperty?HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServices\ -ErrorAction SilentlyContinue | Out-File -Append Service_Control_HKEY_Baseline.txt

Write-Host "Almost Done"

# Generate an MSINFO32.EXE report, which includes lots of misc info.
Write-Verbose -Message "Writing to MSINFO32-Report.txt" 
msinfo32.exe /report MSINFO32-Report.txt

# Gather .exe files created w/in the last 24 hours, and dump to CSV
Get-ChildItem -path $SCANDIR -Recurse -force -file -ErrorAction SilentlyContinue | where-object {($_.extension -eq ".exe") -and ($_.CreationTime -gt (get-date).AddDays(-1))} | Out-File 24hrEXE.txt

# Hidden Files and Folders 
dir -Path c:\ -Hidden -Recurse -ErrorAction SilentlyContinue | Select-Object FullName,Length,Mode,CreationTime,LastAccessTime,LastWriteTime | Out-File Hidden_Files_and_Folders.txt


# Non-Hidden Files and Folders
dir -Path c:\ -Recurse -ErrorAction SilentlyContinue | Select-Object FullName,Length,Mode,CreationTime,LastAccessTime,LastWriteTime | Out-File Non_Hidden_Files_and_Folders.txt

#Pull Important Hashes
Get-FileHash -Algorithm SHA1 -Path C:\XXXX\* > Startup_Hash.txt

# Save hashes and full paths to the snapshot files to a CSV:
# if (Get-Command -Name Get-FileHash -ErrorAction SilentlyContinue)
# {
#     $hashes = dir -File | Get-FileHash -Algorithm SHA256 -ErrorAction SilentlyContinue 
#     $hashes | Export-Csv -Path Snapshot-File-Hashes.csv -Force  #cannot directly pipe
# }


# NTFS Permissions And Integrity Labels
# This file can reach 100's of MB in size, so
# we'll limit this example to just System32:
# icacls.exe c:\windows\system32 /t /c /q 2>$null | Out-File -FilePath FileSystem-NTFS-Permissions.txt


###############################################################################
#
#  The following commands require that various tools be installed and in the 
#  PATH, since they are not installed by default.  Uncomment the lines after 
#  installing the tools.
#
###############################################################################

# Sysinternals AutoRuns; not in the PATH by default even when
# installed; get from microsoft.com/sysinternals

#########   autorunsc.exe -accepteula -a -c | Out-File -FilePath AutoRuns.csv


# SHA256 File Hashes
# Takes a long time! Requires lots of space!
# Add more paths as you wish of course, this is just to get started.
# sha256deep.exe is used instead of Get-FileHash because it's faster.

#########   sha256deep.exe -s "c:\*" | Out-File -FilePath Hashes-C.txt
#########   sha256deep.exe -s "d:\*" | Out-File -FilePath Hashes-D.txt
#########   sha256deep.exe -s -r ($env:PROGRAMFILES + "\*") | Out-File -FilePath Hashes-ProgramFiles.txt 
#########   sha256deep.exe -s -r ($env:SYSTEMROOT + "\*") | Out-File -FilePath Hashes-SystemRoot.txt



###############################################################################
#
#  Perform final tasks, such as writing to an event log, cleaning up temp files, 
#  compressing the folder into an archive, moving the archive into a shared folder,
#  etc. This can also be done in an external wrapper script run as a scheduled task.
#
###############################################################################

# Delete any leftover temp files?  What about the hashes list?  (del *.tmp) 

# Set read-only bit on files created?  (attrib.exe +R *.txt)

# Write to the event log about the snapshot process?  (write-eventlog)  



###############################################################################
#
# THIS COMMAND MUST BE LAST: Go back to the original working directory:
#
###############################################################################

Write-Host "Baseline Script Complete"

#Automatic Compression in Powershell V5.0
#Compress-Archive -path $dirName -DestinationPath "C:\TEMP\'$dirName'

exit
