﻿<#
.Synopsis
	Exports MS SQL script for an object from the given server.

.Description
	This allows exporting a single database object to a SQL script, rather than
	a whole database as Export-DatabaseScripts.ps1 does.

	It can be particularly useful for creating an object-drop script, with all dependencies.

.Parameter Server
	The name of the server (and instance) to connect to.

.Parameter Database
	The name of the database to connect to on the server.

.Parameter Urn
	The Urn of the database object to script.
	Example: "Server[@Name='ServerName\Instance']/Database[@Name='DatabaseName']/Table[@Name='TableName' and @Schema='dbo']"

.Parameter Table
	The unquoted name of the table to script.
	Resolved using the Schema parameter.

.Parameter View
	The unquoted name of the view to script.
	Resolved using the Schema parameter.

.Parameter StoredProcedure
	The unquoted name of the stored procedure to script.
	Resolved using the Schema parameter.

.Parameter UserDefinedFunction
	The unquoted name of the user defined function to script.
	Resolved using the Schema parameter.

.Parameter Schema
	The unquoted name of the schema to use with the Table, View, StoredProcedure, or UserDefinedFunction parameters.
	Defaults to dbo.

.Parameter FilePath
	The file to export the script to.

.Parameter Encoding
	The file encoding to use for the SQL scripts.

.Parameter Append
	Indicates the file should be appended to, rather than replaced.
	Useful when piping a list of objects to be scripted to a file.

.Parameter ScriptingOptions
	Provides a list of boolean SMO ScriptingOptions properties to set to true.

.Parameter SqlVersion
	The SQL version to target when scripting.
	By default, uses the version from the source server.
	Versions greater than the source server's version may fail.

.Inputs
	System.Data.DataRow, INFORMATION_SCHEMA.TABLES or INFORMATION_SCHEMA.ROUTINES records.

.Component
	Microsoft.SqlServer.Smo.Server

.Component
	Microsoft.SqlServer.Management.Smo.ScriptingOptions

.Link
	Export-DatabaseScripts.ps1

.Link
	Install-SqlServerModule.ps1

.Link
	https://msdn.microsoft.com/library/microsoft.sqlserver.management.smo.aspx

.Link
	https://msdn.microsoft.com/library/microsoft.sqlserver.management.smo.scriptingoptions_properties.aspx

.Link
	https://msdn.microsoft.com/library/cc646021.aspx

.Example
	Export-DatabaseObjectScript.ps1 ServerName\instance AdventureWorks2014 -Table Customer -Schema Sales -FilePath Sales.Customer.sql
	Exports table creation script to Sales.Customer.sql as UTF8.

.Example
	Export-DatabaseObjectScript.ps1 ServerName\instance AdventureWorks2014 -Table Customer -Schema Sales -FilePath DropCustomer.sql ScriptDrops WithDependencies SchemaQualify IncludeDatabaseContext
	Exports drop script of Sales.Customer and dependencies to DropCustomer.sql.
#>

#Requires -Version 3
#Requires -Module SqlServer
[CmdletBinding()][OutputType([void])] Param(
[Parameter(Position=0,Mandatory=$true)][Alias('ServerInstance')][string] $Server,
[Parameter(Position=1,Mandatory=$true,ValueFromPipelineByPropertyName=$true)][Alias('TABLE_CATALOG','ROUTINE_CATALOG')][string] $Database,
[Parameter(ParameterSetName='Urn',Mandatory=$true)][string] $Urn,
[Parameter(ParameterSetName='Table',Mandatory=$true,ValueFromPipelineByPropertyName=$true)][Alias('TABLE_NAME')][string] $Table,
[Parameter(ParameterSetName='View',Mandatory=$true)][string] $View,
[Parameter(ParameterSetName='StoredProcedure',Mandatory=$true,ValueFromPipelineByPropertyName=$true)][Alias('ROUTINE_NAME','Procedure','SProcedure')][string] $StoredProcedure,
[Parameter(ParameterSetName='UserDefinedFunction',Mandatory=$true)][Alias('UDF','Function')][string] $UserDefinedFunction,
[Parameter(ValueFromPipelineByPropertyName=$true)][Alias('TABLE_SCHEMA','ROUTINE_SCHEMA')][string] $Schema = 'dbo',
[Parameter(Mandatory=$true)][string] $FilePath,
[ValidateSet('Unicode','UTF7','UTF8','UTF32','ASCII','BigEndianUnicode','Default','OEM')][string]$Encoding = 'UTF8',
[switch]$Append,
[Parameter(ValueFromRemainingArguments=$true)][string[]] $ScriptingOptions =
	'EnforceScriptingOptions ExtendedProperties Permissions DriAll Indexes Triggers ScriptBatchTerminator' -split '\s+',
[Microsoft.SqlServer.Management.Smo.SqlServerVersion]$SqlVersion
)
Begin
{
	# connect to database
	$srv = New-Object Microsoft.SqlServer.Management.Smo.Server($Server)
	if(!$SqlVersion)
	{
		[Microsoft.SqlServer.Management.Smo.SqlServerVersion]$SqlVersion = "Version$($srv.VersionMajor)$($srv.VersionMinor/10)"
	}
}
Process
{
	$db = $srv.Databases[$Database]
	if(!$db) {return}
	Write-Verbose "Connected to $srv.$db $($srv.Product) $($srv.Edition) $($srv.VersionString) $($srv.ProductLevel) (Windows $($srv.OSVersion))"

	# set up scripting options
	$opts = New-Object Microsoft.SqlServer.Management.Smo.ScriptingOptions
	Write-Verbose "Targeting SQL version: $SqlVersion"
	$opts.TargetServerVersion = $SqlVersion
	$ScriptingOptions |
		% {
			if(($opts |Get-Member $_) -and $opts.$_ -is [bool]) {$opts.$_ = $true}
			else {Write-Warning "Not a boolean scripting option: '$_'"}
		}
	if($Append){$opts.AppendToFile=$true}
	$opts.ToFileOnly = $true
	$opts.FileName = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($FilePath)
	$opts.Encoding =
		if($Encoding -eq 'OEM') {$OutputEncoding.GetEncoder().Encoding}
		else {[Text.Encoding]::$Encoding}
	Write-Verbose "Scripting options flags: $(($opts |Get-Member -MemberType Property |% Name |? {$opts.$_ -is [bool] -and $opts.$_}) -join ', ')"
	Write-Verbose "Scripting options values: $(($opts |Get-Member -MemberType Property |% Name |? {$opts.$_ -isnot [bool] -and $opts.$_} |% {"$_=$($opts.$_)"}) -join ', ')"

	$object =
		if($Urn) { $db.Resolve($Urn) }
		elseif($Table) { $db.Tables[$Table,$Schema] }
		elseif($View) { $db.Views[$View,$Schema] }
		elseif($StoredProcedure) { $db.StoredProcedures[$StoredProcedure,$Schema] }
		elseif($UserDefinedFunction) { $db.UserDefinedFunctions[$UserDefinedFunction,$Schema] }
	if(!$object){throw "Could not find object: $(ConvertTo-Json $PSBoundParameters -Compress)"}

	$object.Script($opts)
}
