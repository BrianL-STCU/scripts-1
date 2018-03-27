<#
.Synopsis
    Returns the content security policy at from the given URL.

.Parameter Uri
    The URL to get the policy from.

.Parameter Response
    The output from Invoke-WebRequest to parse the policy from.

.Inputs
    Microsoft.PowerShell.Commands.WebResponseObject from Invoke-WebRequest
    or
    any object with a Uri or Url property

.Outputs
    System.Management.Automation.PSCustomObject containing the parsed policy

.Link
    https://content-security-policy.com/

.Link
    Invoke-WebRequest

.Example
    Invoke-WebRequest http://example.org/ |Get-ContentSecurityPolicy.ps1

    default-src : {http://example.org, http://example.net, 'self'}
    script-src  : {'self'}
    img-src     : {'self'}
    report-uri  : {http://example.com/csp}
#>

#Requires -Version 3
[CmdletBinding()]Param(
[Parameter(ParameterSetName='Uri',Position=0,Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
[Alias('Url')][Uri]$Uri,
[Parameter(ParameterSetName='Response',Mandatory=$true,ValueFromPipeline=$true)]
[Microsoft.PowerShell.Commands.WebResponseObject]$Response
)
Process
{
    if($Uri){$Response = Invoke-WebRequest $Uri -UseBasicParsing}
    if(!$Response.Headers.ContainsKey('Content-Security-Policy')){return}
    $csp = @{}
    $Response.Headers['Content-Security-Policy'] -split '\s*;\s*' |
        % {$directive,$values=$_ -split '\s+'; $csp[$directive]=[string[]]$values}
    return [pscustomobject]$csp
}
