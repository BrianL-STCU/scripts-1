<#
.Synopsis
	Returns a date/time as a named format.

.Parameter Format
	The format to serialize the date as.

.Parameter Date
	The date/time value to format.

.Link
	Get-Date

.Example
	Format-Date Iso8601WeekDate 2021-01-20

	2021-W03-3

.Example
	'Feb 2, 2020 8:20 PM +00:00' |Format-Date Iso8601Z

	2020-02-02T20:20:00Z
#>

#Requires -Version 3
[CmdletBinding()][OutputType([string])] Param(
[Parameter(Position=0,Mandatory=$true)]
[ValidateSet('FrenchRepublicanDateTime','Iso8601','Iso8601Date','Iso8601OrdinalDate',
'Iso8601Week','Iso8601WeekDate','Iso8601Z','Rfc1123')]
[string] $Format,
[Parameter(Position=1,ValueFromPipeline=$true)][datetime] $Date = (Get-Date)
)
Process
{
	switch($Format)
	{
		FrenchRepublicanDateTime {"$(Get-FrenchRepublicanDate.ps1 $Date)"}
		Iso8601 {Get-Date $Date -f "yyyy'-'MM'-'dd'T'HH':'mm':'sszzzz"}
		Iso8601Date {Get-Date $Date -uf %F}
		Iso8601OrdinalDate {Get-Date $Date -uf "%Y-$('{0:000}' -f $Date.DayOfYear)"}
		Iso8601Week {Get-Date $Date -uf %Y-W%V}
		Iso8601WeekDate {$w = [int]$Date.DayOfWeek; if($w -eq 0) {$w = 7}; Get-Date $Date -uf %Y-W%V-$w}
		Iso8601Z {Get-Date $Date.ToUniversalTime() -f "yyyy'-'MM'-'dd'T'HH':'mm':'ss'Z'"}
		Rfc1123 {Get-Date $Date -uf '%a, %e %b %Y %T %Z'}
	}
}
