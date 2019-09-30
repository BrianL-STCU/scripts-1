﻿<#
.Synopsis
	Determines whether a string is a valid JWT.

.Parameter InputObject
    The string to test.

.Parameter Secret
    The secret used to sign the JWT.

.Inputs
	System.String value to test for a valid URI format.

.Outputs
	System.Boolean indicating that the string can be parsed as a URI.

.Example
	Test-Jwt.ps1 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOjE1MTYyMzkwMjIsInN1YiI6IjEyMzQ1Njc4OTAifQ.-zAn1et1mf6QHakJbOTt5-p4gv33R7cIikKy8-9aiNs' (ConvertTo-SecureString swordfish -AsPlainText -Force)

    True
#>

#Requires -Version 3
[CmdletBinding()][OutputType([bool])] Param(
[Parameter(Position=0,Mandatory=$true,ValueFromPipeline=$true)][AllowEmptyString()][AllowNull()][string] $InputObject,
[Parameter(Position=1,Mandatory=$true)][SecureString] $Secret
)
Begin
{
    function ConvertFrom-Base64Url([string]$s)
    {[Convert]::FromBase64String(($s -replace '-','+' -replace '_','/').PadRight($s.Length + (4 - $s.Length % 4) % 4, '='))}
}
Process
{
    if(!$InputObject) {Write-Verbose 'No JWT input'; return $false}
    if(!$InputObject.Contains([char]'.')) {Write-Verbose 'JWT is missing a dot'; return $false}
    $head64,$body64,$sign64 = $InputObject -split '\.'
    $head = [Text.Encoding]::UTF8.GetString((ConvertFrom-Base64Url $head64))
    Write-Verbose "JWT head: $head"
    if(!(Test-Json.ps1 $head)) {Write-Verbose 'JWT header does not decode to valid JSON'; return $false}
    $head = ConvertFrom-Json $head
    if($head.typ -ne 'JWT') {Write-Verbose "JWT type is $($head.typ)"; return $false}
    if($head.alg -notin 'HS256','HS384','HS512') {Write-Verbose "Unsupported algorithm: $($head.alg)"; return $false}
    $body = [Text.Encoding]::UTF8.GetString((ConvertFrom-Base64Url $body64))
    Write-Verbose "JWT body: $body"
    if(!(Test-Json.ps1 $body)) {Write-Verbose 'JWT body does not decode to valid JSON'; return $false}
    $body = ConvertFrom-Json $body
    [byte[]]$sign = ConvertFrom-Base64Url $sign64
    $secred = New-Object pscredential 'secret',$Secret
    [byte[]]$secbytes = [Text.Encoding]::UTF8.GetBytes($secred.GetNetworkCredential().Password)
    $hash = New-Object "Security.Cryptography.$($head.alg -replace '\AHS','HMACSHA')" (,$secbytes)
    if(compare $sign ($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes("$head64.$body64"))))
    {Write-Verbose "JWT hashes do not match"; return $false}
    return $true
}
