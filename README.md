# GetMissingUpdates
## Purpose
The purpose of this script is to check for updates offline using a scan cab file.

## Usage
As described here https://blogs.technet.microsoft.com/japete/?p=35&preview=true the script can be used like this:
```powershell
# With an already downloaded file
.\GetMissingUpdates.ps1 -ComputerName serverA,serverB,serverC -Path D:\wsusscn2.cab -Credential (Get-Credential) -Verbose
# Or with the automatic download capabilities
.\GetMissingUpdates.ps1 -ComputerName serverA,serverB,serverC -DownloadUri http://go.microsoft.com/fwlink/?linkid=74689 -Credential (Get-Credential) -Verbose
```
