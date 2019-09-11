# GetMissingUpdates
## Purpose
The purpose of this script is to check for updates offline using a scan cab file.

## Usage
In order to use this script, you need to fulfil the following requirements:
- Host system (i.e. the collecting machine): PowerShell 4+
- Target systems: PowerShell 2+
- ***Please update to PSv5 nevertheless. Running PSv2 puts you at a tremendous risk, regardless of how many patches you install.***
- Either a downloaded wsusscan2.cab or Internet connectivity on the ***host*** system
- Either PowerShell Remoting enabled on all systems (Enable-PSRemoting) or DCOM

```powershell
# With an already downloaded file
.\GetMissingUpdates.ps1 -ComputerName serverA,serverB,serverC -Path D:\wsusscn2.cab -Credential (Get-Credential) -Verbose

# Or with the automatic download capabilities
.\GetMissingUpdates.ps1 -ComputerName serverA,serverB,serverC -DownloadUri http://go.microsoft.com/fwlink/?linkid=74689 -Credential (Get-Credential) -Verbose
```

This method uses distributed COM and an Activator instance to scan the remote systems. Should you require the use of WinRM sessions, simply use the parameter ```UseDcomOverWinRm``` to create the Activator from within a WinRM session to the remote host.

Regardless of the method you use, the scan cab file needs to be transferred to each remote system and will ***only*** be removed automatically afterwards if you opted to wait for the jobs to finish. This script attempts to select the fastest available method to copy the file to the remote systems.

### Runtime

Scanning wave after wave of your own systems requires time. This is why in the recent iteration of this script jobs will be returned. Should you want to wait, simply use the ```Wait``` parameter. In this case, the results will be returned.
