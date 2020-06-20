﻿<#
.Synopsis
    Copy scheduled jobs from another computer to this one, using a GUI list to choose jobs.

.Parameter ComputerName
    The name of the computer to copy jobs from.

.Parameter DestinationComputerName
    The name of the computer to copy jobs to (local computer by default).

.Example
    Copy-SchTasks.ps1 SourceComputer DestComputer

    Attempts to copy tasks from SourceComputer to DestComputer.
#>

#Requires -Version 2
[CmdletBinding()][OutputType([void])] Param(
[Parameter(Mandatory=$true,Position=0)][Alias('CN','Source')][string]$ComputerName,
[Parameter(Position=1)][Alias('To','Destination')][string]$DestinationComputerName = $env:COMPUTERNAME
)
$TempXml= [io.path]::GetTempFileName()
$CredentialCache = @{}
function Get-CachedCredentialFor([Parameter(Mandatory=$true,Position=0)][string]$UserName)
{
    if(!$CredentialCache.ContainsKey($UserName))
    { $CredentialCache.Add($UserName,(Get-Credential -Message "Enter credentials for $UserName tasks" -UserName $UserName)) }
    $CredentialCache[$UserName]
}
function ConvertFrom-Credential
([Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)][PSCredential][Management.Automation.Credential()]$Credential)
{ $Credential.GetNetworkCredential().Password }
schtasks /query /s $ComputerName /v /fo csv |
    ConvertFrom-Csv |
    ? {$_.HostName -ne 'HostName'} |
    Out-GridView -PassThru -Title 'Select jobs to copy' |
    select TaskName,'Run As User' -Unique |
    % {
        schtasks /query /s $ComputerName /tn $_.TaskName /xml ONE |
            Out-File $TempXml unicode -Width ([int]::MaxValue)
        schtasks /create /s $DestinationComputerName /tn $_.TaskName /ru ($_.'Run As User') `
            /rp (Get-CachedCredentialFor $_.'Run As User' |
            ConvertFrom-Credential) /xml $TempXml
        rm $TempXml
    }
$CredentialCache.Clear()
