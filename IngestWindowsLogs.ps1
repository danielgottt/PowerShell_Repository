<##############################################################################
.SYNOPSIS

  Script referenced in "Offline ELK stack for Air Gapped Windows Logs" Crew Aid
  
    Created by: 01000111
.DESCRIPTION
      Manually upload airgapped Windows logs into your own ELK stack. The file path you designate in $Path1 should reflect some kind of host 
      detail that will allow you to identify where the log came from. This is to battle reused hostname's on these windows machines.
##############################################################################>

# Change this line to the path containing your evtx/raw logs
$Path1 = "C:\Logs\HostSerialNumber\windowslogfolderdate"

# Now we filter for just the .evtx/.evt files
$Dir1 = Get-ChildItem -Path $Path1 -filter *.evtx, *.evt

# The for loop to import all the logs!
foreach($file in $Dir1){
   $filePath = $Path1 + "\" + $file
   Write-Host $filePath
   .\winlogbeat.exe -e -c .\winlogbeat-evtx.yml -E EVTX_FILE="$filePath"
   Sleep 2
}
