<#
.Synopsis
	Returns the creation and last modification metadata for a file in a git repo.

.Parameter Path
	The path (or paths) to get metadata for.

.Parameter Recurse
	Recurse into subdirectories.

.Link
	Use-Command.ps1

.Link
	Get-ChildItem

.Link
	Resolve-Path

.Example
	Get-GitFileMetadata.ps1 README.md

	Path         : .\README.md
	CreateCommit : 1fde7af
	CreateAuthor : Brian Lalonde
	CreateEmail  : brianary@gmail.com
	CreateDate   : 01/19/2015 11:44:15
	LastCommit   : dbe27ba
	LastAuthor   : Brian Lalonde
	LastEmail    : brianary@gmail.com
	LastDate     : 12/07/2020 20:17:15
#>

#Requires -Version 3
[CmdletBinding()][OutputType([psobject])] Param(
[Parameter(Position=0,Mandatory=$true,ValueFromPipelineByPropertyName=$true,ValueFromRemainingArguments=$true)]
[string[]] $Path,
[switch] $Recurse
)
Begin { Use-Command.ps1 git "$env:ProgramFiles\Git\cmd\git.exe" -choco git }
Process
{
	foreach($f in Get-ChildItem $Path -Recurse:$Recurse)
	{
		$create_commit,$create_author,$create_email,$create_date =
			(git log --reverse --format="%h%x09%cn%x09%ae%x09%ai" $f |select -f 1) -split '\t'
		$last_commit,$last_author,$last_email,$last_date =
			(git log -1 --format="%h%x09%cn%x09%ae%x09%ai" $f |select -f 1) -split '\t'
		[pscustomobject]@{
			Path = Resolve-Path $f -Relative
			CreateCommit = $create_commit
			CreateAuthor = $create_author
			CreateEmail = $create_email
			CreateDate = [datetime]$create_date
			LastCommit = $last_commit
			LastAuthor = $last_author
			LastEmail = $last_email
			LastDate = [datetime]$last_date
		}
	}
}
