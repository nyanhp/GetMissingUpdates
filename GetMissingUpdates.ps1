#requires -Version 4
<#
.SYNOPSIS
    Script to search updates
.DESCRIPTION
    Script to search for missing security updates on remote endpoints used in the Microsoft Baseline Security Analyser
.PARAMETER ComputerName
    The machine to connect to
.PARAMETER Path
    The path to the offline scan file
.PARAMETER DownloadUri
    THe URI to download wsusscn2.cab from
.PARAMETER UpdateSearchFilter
    The actual search filter. Default value 'IsHidden = 0'
.PARAMETER Credential
    The credential to use instead of using Kerberos
.NOTES
    Author: Jan-Hendrik Peters, Andreas Mirbach
# Disclaimer
# This module and it's scripts are not supported under any Microsoft standard support program or service.
# The scripts are provided AS IS without warranty of any kind.
# Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability
# or of fitness for a particular purpose.
# The entire risk arising out of the use or performance of the scripts and documentation remains with you.
# In no event shall Microsoft, its authors, or anyone else involved in the creation, production,
# or delivery of the scripts be liable for any damages whatsoever (including, without limitation, damages
# for loss of business profits, business interruption, loss of business information, or other pecuniary loss)
# arising out of the use of or inability to use the sample scripts or documentation,
# even if Microsoft has been advised of the possibility of such damages.
#>
param
(
    [Parameter(Mandatory = $true)]
    [System.String[]]
    $ComputerName,

    [Parameter(Mandatory = $true, ParameterSetName = 'Path')]
    [System.String]
    $Path,

    # As of Sep 2017 http://go.microsoft.com/fwlink/?linkid=74689
    [Parameter(Mandatory = $true, ParameterSetName = 'Url')]
    [System.String]
    $DownloadUri,

    [Parameter()]
    [System.String]
    $UpdateSearchFilter = 'IsHidden = 0',

    [Parameter()]
    [pscredential]
    $Credential
)

if ($DownloadUri)
{
    $Path = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath wsusscn2.cab

    Invoke-WebRequest -Uri $DownloadUri -OutFile $Path
}

function Send-File
{
    <#
            .SYNOPSIS

            Sends a file to a remote session.

            .EXAMPLE

            PS >$session = New-PsSession leeholmes1c23
            PS >Send-File c:\temp\test.exe c:\temp\test.exe $session
    #>
	
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Source,
		
        [Parameter(Mandatory = $true)]
        [string]
        $Destination,
		
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Runspaces.PSSession[]]
        $Session,

        $ChunkSize = 1MB
    )
	
    #Set-StrictMode -Version Latest
    $firstChunk = $true
	
    Write-Host "PSFileTransfer: Sending file $Source to $Destination on $($Session.ComputerName) ($([Math]::Round($chunkSize / 1MB, 2)) MB chunks)"
	
    $sourcePath = (Resolve-Path $Source -ErrorAction SilentlyContinue).Path
    if (-not $sourcePath)
    {
        Write-Host ('Source file {0} could not be found' -f $Source)
        throw ('Source file {0} could not be found' -f $Source)
    }
	
    $sourceFileStream = [IO.File]::OpenRead($sourcePath)
	
    for ($position = 0; $position -lt $sourceFileStream.Length; $position += $chunkSize)
    {        
        $remaining = $sourceFileStream.Length - $position
        $remaining = [Math]::Min($remaining, $chunkSize)
		
        $chunk = New-Object -TypeName byte[] -ArgumentList $remaining
        [void]$sourceFileStream.Read($chunk, 0, $remaining)
		
        try
        {
            #Write-File -DestinationFile $Destination -Bytes $chunk -Erase $firstChunk
            Invoke-Command -Session $Session -ScriptBlock (Get-Command Write-File).ScriptBlock `
                -ArgumentList $Destination, $chunk, $firstChunk -ErrorAction Stop
        }
        catch [System.Exception]
        {
            Write-Host ('Could not write destination file. {0}' -f $_.Exception.Message)
            throw $_.Exception
        }
		
        $firstChunk = $false
    }
	
    $sourceFileStream.Close()
	
    Write-Host "PSFileTransfer: Finished sending file $Source"
}
function Write-File
{
    param (
        [Parameter(Mandatory = $true)]
        [string]$DestinationFile,
		
        [Parameter(Mandatory = $true)]
        [byte[]]$Bytes,
		
        [bool]$Erase
    )
	
    #Convert the destination path to a full filesytem path (to support relative paths)
    try
    {
        $DestinationFile = $executionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($DestinationFile)
    }
    catch [System.Exception]
    {
        Write-Host ('Could not set destination path to {0} to copy item through the remote session. {1}' -f $DestinationFile, $_.Exception.Message)
        throw New-Object -TypeName System.IO.FileNotFoundException -ArgumentList ('Could not set destination path', $_)
    }
	
    if ($Erase)
    {
        Remove-Item $DestinationFile -Force -ErrorAction SilentlyContinue
    }
	
    $destFileStream = [IO.File]::OpenWrite($DestinationFile)
    $destBinaryWriter = New-Object -TypeName System.IO.BinaryWriter -ArgumentList ($destFileStream)
	
    [void]$destBinaryWriter.Seek(0, 'End')
    $destBinaryWriter.Write($Bytes)
	
    $destBinaryWriter.Close()
    $destFileStream.Close()
	
    $Bytes = $null
    [GC]::Collect()
}

function Get-MissingUpdates
{
    param
    (
        [string[]]
        $ComputerName,

        [string]
        $Path,

        [Parameter()]
        [System.String]
        $UpdateSearchFilter = 'IsHidden = 0',

        [Parameter()]
        [pscredential]
        $Credential
    )

    Write-Host ('Creating sessions to {0}' -f ($ComputerName -join ','))

    $remoteScript = {
        param
        (
            [string]$destination,
            [string]$UpdateSearchFilter,
            $remoteScript
        )

        Add-Type -TypeDefinition "
        public enum MsrcSeverity
        {
            Unspecified,
            Low,
            Moderate,
            Important,
            Critical
        }
        " -ErrorAction SilentlyContinue

        if (@(1, 2, 3, 4, 6, 11, 27, 28, 48) -contains (Get-WmiObject Win32_OperatingSystem).OperatingSystemSKU -and $remoteScript) # Client SKUs
        {
            Write-Host 'Client SKU. Registering script as scheduled task'

            if ($PSVersionTable.PSVersion -lt 3.0.0.0)
            {
                throw 'Upgrade my WMF version, please.'
            }
            
            $localScript = [scriptblock]::Create($remoteScript)
            if (Get-ScheduledJob WorkaroundJob -ErrorAction SilentlyContinue)
            {
                Unregister-ScheduledJob -Name WorkaroundJob -Force
            }

            # On client SKUs, WU-APIs are remoting-aware. We trick them be starting a scheduled job
            $job = Register-ScheduledJob -ScriptBlock $localScript -Name WorkaroundJob -ArgumentList @($destination, $UpdateSearchFilter)
            $job.RunAsTask()

            Start-Sleep -Seconds 1

            $job = Get-Job -Name WorkaroundJob | Where-Object -Property State -eq Running

            $jobResult = $job | Wait-Job | Receive-Job
            return $jobResult
        }

        if (-not (Test-Path -Path $destination))
        {
            throw "Unable to locate $destination. Cancelling..."
        }

        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateServiceManager = New-Object -ComObject Microsoft.Update.ServiceManager

        try 
        {
            $UpdateService = $UpdateServiceManager.AddScanPackageService("Offline Sync Service", $Destination)
            Write-Host "Successfully added scan service with $destination"
        }
        catch 
        {
            $exceptionObject = $_
            switch (('{0:x}' -f $exceptionObject.Exception.GetBaseException().HResult))
            {
                # E_ACCESSDENIED
                '80070005' 
                {
                    Write-Error -Message 'AddScanPackageService received an AccessDenied exception.' -Exception $exceptionObject.Exception -Category PermissionDenied -TargetObject $Destination
                    return $null
                }
                # E_INVALIDARG
                '80070057' 
                {
                    Write-Error -Message ('AddScanPackageService received one or more invalid arguments. Arguments were {0}, {1}' `
                            -f 'Offline Sync Service', $Destination) -Exception $exceptionObject.Exception -Category InvalidArgument -TargetObject $Destination
                    return $null
                }
                # File not found
                '80070002' 
                {
                    Write-Error -Message ('{0} could not be found.' -f $Destination) -Exception $exceptionObject.Exception -Category ObjectNotFound -TargetObject $Destination
                    return $null
                }
                default
                {
                    throw $exceptionObject
                }
            }
        }        

        try
        {
            $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
            Write-Host "Update searcher created from update session"
        }
        catch
        {
            Write-Error -Message 'CreateUpdateSearcher threw a generic error' -Exception $_.Exception -TargetObject $UpdateSession
        }

        # corresponds to ss_others https://msdn.microsoft.com/en-us/library/windows/desktop/aa387280(v=vs.85).aspx
        $UpdateSearcher.ServerSelection = 3
        $UpdateSearcher.ServiceID = $UpdateService.ServiceID
        #$UpdateSearcher.Online = $false

        # Initiate the search
        try
        {
            $SearchResult = $UpdateSearcher.Search($UpdateSearchFilter)
            Write-Host "Finished searching for Updates with filter '$UpdateSearchFilter'"
        }
        catch
        {
            $exceptionObject = $_
            switch (('{0:x}' -f $exceptionObject.Exception.GetBaseException().HResult))
            {
                #WU_E_LEGACYSERVER
                '80004003'
                {
                    Write-Error -Message ('Target {0} is Microsoft Software Update Services (SUS) 1.0 server.' -f $ComputerName) -Exception $exceptionObject.Exception
                    return $null
                }
                #E_POINTER
                '8024002B'
                {
                    Write-Error -Message ('Search received invalid argument {0}' `
                            -f $UpdateSearchFilter) -Exception $exceptionObject.Exception -Category InvalidArgument -TargetObject $Destination
                    return $null
                }
                #WU_E_INVALID_CRITERIA
                '80240032'
                {
                    Write-Error -Message ('Invalid search filter: {0}' `
                            -f $UpdateSearchFilter) -Exception $exceptionObject.Exception -Category InvalidArgument -TargetObject $Destination
                    return $null
                }
                default
                {
                    throw $exceptionObject
                }
            }
        }
        
        $missingUpdates = @()
        foreach ($result in $SearchResult.Updates)
        {
            $downloadUrl = $result.BundledUpdates | ForEach-Object {
                $_.DownloadContents | ForEach-Object {
                    $_.DownloadUrl
                }
            } | Select-Object -First 1

            $severity = 0

            try 
            {
                $severity = ([int][MsrcSeverity]$result.MsrcSeverity)
            }
            catch 
            { }

            $bulletinId = ($result.SecurityBulletinIDs | Select-Object -First 1)
            $bulletinUrl = if ($bulletinId) 
            {
                'http://www.microsoft.com/technet/security/bulletin/{0}.mspx' -f $bulletinId
            }
            else
            {
                [System.String]::Empty
            }    

            $update = New-Object -TypeName psobject |
                Add-Member -MemberType NoteProperty -Name Id -Value ($result.SecurityBulletinIDs | Select-Object -First 1) -PassThru -Force |
                Add-Member -MemberType NoteProperty -Name Guid -Value $result.Identity.UpdateId -PassThru -Force |
                Add-Member -MemberType NoteProperty -Name BulletinId -Value $bulletinId -PassThru -Force |
                Add-Member -MemberType NoteProperty -Name KbId -Value ($result.KBArticleIDs | Select-Object -First 1) -PassThru -Force |
                Add-Member -MemberType NoteProperty -Name Type -Value $result.Type -PassThru -Force |
                Add-Member -MemberType NoteProperty -Name IsInstalled -Value $result.IsInstalled -PassThru -Force |
                Add-Member -MemberType NoteProperty -Name RestartRequired -Value $result.RebootRequired -PassThru -Force |
                Add-Member -MemberType NoteProperty -Name Title -Value $result.Title -PassThru -Force |
                Add-Member -MemberType NoteProperty -Name InformationURL -Value ($result.MoreInfoUrls | Select-Object -First 1) -PassThru -Force |
                Add-Member -MemberType NoteProperty -Name SeverityText -Value $result.MsrcSeverity -PassThru -Force |
                Add-Member -MemberType NoteProperty -Name Severity -Value $severity -PassThru -ErrorAction SilentlyContinue -Force |
                Add-Member -MemberType NoteProperty -Name DownloadURL -Value $downloadUrl -PassThru -Force |
                Add-Member -MemberType NoteProperty -Name BulletinURL -Value $bulletinUrl -PassThru -Force

            $missingUpdates += $update
        }

        try
        {
            Write-Host ('Removing WSUS offline file {0}' -f $Destination)
            Remove-Item -Path $Destination -Force -ErrorAction Stop
        }
        catch
        {
            Write-Warning -Message ('WSUS offline file {0} could not be removed. Error was {1}' -f $Destination, $_.Exception.Message)
        }
        return $missingUpdates
    }

    $remoteJobs = foreach ( $computer in $ComputerName)
    {        

        Start-Job -Name "RemoteUpdateCheck_$computer" -ScriptBlock {
            param(
                $computer,
                $Path,
                $UpdateSearchFilter,
                $remoteScript,
                $Credential
            )
            $sessionParameters = @{
                ComputerName = $computer
                ErrorAction  = 'Stop'
                Name         = 'WuaSession'
            }
        
            $remoteScript = [scriptblock]::Create($remoteScript)

            if ($Credential)
            {
                $sessionParameters.Add('Credential', $Credential)
            }
    
            try
            {
                $session = New-PSSession @sessionParameters
            }
            catch
            {
                Write-Host ('Error establishing connection to {0}. Error message was {1}' -f $computer, $_.Exception.Message) 
                Write-Error -Message ('Error establishing connection to {0}. Error message was {1}' -f $computer, $_.Exception.Message) -Exception $_.Exception -TargetObject $computer
                return $null
            }

            try
            {
                $osRoot = Invoke-Command -Session $session -ScriptBlock { $env:SystemDrive } -ErrorAction Stop
            }
            catch
            {
                Write-Host ('Error retrieving OS root path from {0}. Assuming issue with the connection. Error was {1}' -f $computer, $_.Exception.Message)
                Write-Error -Message ('Error retrieving OS root path from {0}. Assuming issue with the connection. Error was {1}' -f $computer, $_.Exception.Message)
            }
    
            try
            {
                $osPSVersion = Invoke-Command -Session $session -ScriptBlock { $PSVersionTable.PSVersion.Major } -ErrorAction Stop
            }
            catch
            {
                Write-Host ('Error retrieving OS Powershell version from {0}. Assuming issue with the connection. Error was {1}' -f $computer, $_.Exception.Message)
                Write-Error -Message ('Error retrieving OS Powershell version from {0}. Assuming issue with the connection. Error was {1}' -f $computer, $_.Exception.Message)
            }

            $adminShare = '\\{0}\{1}$' -f $computer, ($osRoot -replace '[:\\]')
            $useSmb = Test-Path $adminShare

            $destination = (Join-Path -Path $osRoot -ChildPath wsusscn2.cab)

            if ($useSmb)
            {
                $smbDestination = (Join-Path -Path $adminShare -ChildPath wsusscn2.cab)

                try
                {
                    Write-Host ('Using Copy-Item to copy {0} to {1} on {2}' -f $Path, $smbDestination, $computer)
                    Copy-Item -Path $Path -Destination $smbDestination -Force -ErrorAction Stop
                }
                catch
                {
                    Write-Host ('Error copying {0} to {1} on target machine {2}' -f $Path, $smbDestination, $computer)
                    Write-Error -Exception $_.Exception -Message ('Error copying {0} to {1} on target machine {2}' -f $Path, $smbDestination, $computer) -TargetObject $Path -Category InvalidOperation
                    return $null
                }
            }
            else
            {
                try
                {
                    if ($PSVersionTable.PSVersion.Major -lt 5 -or $osPSVersion -lt 3)
                    {
                        Write-Host ('Using Send-File to copy {0} to {1} on {2} in 1MB chunks' -f $Path, $destination, $computer)
                        Send-File -Source $Path -Destination $destination -Session $session -ChunkSize 1MB -ErrorAction Stop
                    }
                    else
                    {
                        Write-Host ('Using Copy-Item -ToSession to copy {0} to {1} on {2}' -f $Path, $destination, $computer)
                        Copy-Item -ToSession $session -Path $Path -Destination $destination -ErrorAction Stop
                    }
                }
                catch
                {
                    Write-Host ('Error copying {0} to {1} on target machine {2}' -f $Path, $destination, $computer)
                    Write-Error -Exception $_.Exception -Message ('Error copying {0} to {1} on target machine {2}' -f $Path, $destination, $computer) -TargetObject $Path -Category InvalidOperation
                    return $null
                }
            }

            Invoke-Command -Session $session -ScriptBlock $remoteScript -HideComputerName -ErrorAction Stop -ArgumentList ($destination, $UpdateSearchFilter, $remoteScript)

            $session | Remove-PSSession
        } -ArgumentList @($computer, $Path, $UpdateSearchFilter, $remoteScript, $Credential)
    }

    Write-Verbose -Message ('Waiting for {0} remote jobs to finish' -f $remoteJobs.Count)
    $remoteJobs | Wait-Job

    $returnValues = $remoteJobs | Receive-Job
    return $returnValues
}

$parameters = @{
    ComputerName = $ComputerName
    Path         = $Path
}

if ($UpdateSearchFilter)
{
    $parameters.Add("UpdateSearchFilter", $UpdateSearchFilter)
}

if ($Credential)
{
    $parameters.Add("Credential", $Credential)
}


Get-MissingUpdates @parameters
