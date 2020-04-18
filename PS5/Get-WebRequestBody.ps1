<#
.Synopsis
	Listens on a given port of the localhost, returning the body of a single web request, and responding with an empty 204.

.Parameter Port
	The local port to listen on.

.Link
	Start-HttpListener.ps1

.Link
	Stop-HttpListener.ps1

.Link
	Receive-WebRequest.ps1

.Link
	Read-WebRequest.ps1

.Example
	Get-WebRequestBody.ps1

	(Returns the body of one request to http://localhost:8080/ as a byte array.)
#>

#Requires -Version 3
[CmdletBinding()][OutputType([byte[]])] Param(
[int] $Port = 8080
)
$http = Start-HttpListener.ps1 -Port $Port
$context = Receive-WebRequest.ps1 $http
$context.Request.Headers.Keys |foreach {Write-Verbose "${_}: $($context.Request.Headers[$_])"}
Read-WebRequest.ps1 $context.Request -Encoding byte
$context.Response.StatusCode = 204
$context.Response.Close()
Stop-HttpListener.ps1 $http
