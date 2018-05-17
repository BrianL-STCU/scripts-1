﻿<#
.Synopsis
    Searches a specific subset of files for lines matching a pattern.

.Parameter Pattern
    Specifies the text to find. Type a string or regular expression.
    If you type a string, use the SimpleMatch parameter.

.Parameter Filters
    Specifies wildcard filters that file names must match.

.Parameter Path
    Specifies a path to one or more locations. Wildcards are permitted.
    The default location is the current directory (.).

.Parameter Include
    Wildcard patterns files must match one of (slower than Filter).

.Parameter Exclude
    Wildcard patterns files must not match any of.

.Parameter CaseSensitive
    Makes matches case-sensitive. By default, matches are not case-sensitive.

.Parameter List
    Returns only the first match in each input file.
    By default, Select-String returns a MatchInfo object for each match it finds.

.Parameter NotMatch
    Finds text that does not match the specified pattern.

.Parameter SimpleMatch
    Uses a simple match rather than a regular expression match.
    In a simple match, Select-String searches the input for the text in the Pattern parameter.
    It does not interpret the value of the Pattern parameter as a regular expression statement.

.Parameter NoRecurse
    Disables searching subdirectories.

.Parameter ChooseMatches
    Displays a grid of matches to select a subset from.

.Parameter Open
    Invokes files that contain matches.

.Parameter Blame
    Returns git blame info for matching lines.

.Example
    Find-Lines 'using System;' *.cs "$env:USERPROFILE\Documents\Visual Studio*\Projects" -CaseSensitive -List

    This command searches all of the .cs files in the Projects directory (or directories) and subdirectories,
    returning the matches.
#>

#Requires -Version 3
[CmdletBinding(DefaultParameterSetName='Default')]Param(
    [Parameter(Position=0,Mandatory=$true)][string[]]$Pattern,
    [Parameter(Position=1)][string[]]$Filters,
    [Parameter(Position=2)][string[]]$Path,
    [string[]]$Include,
    [string[]]$Exclude = @('*.dll','*.exe','*.pdb','*.bin','*.cache','*.png','*.gif','*.jpg','*.ico','*.psd','*.obj','*.iso',
        '*.docx','*.xls','*.xlsx','*.pdf','*.rtf','*.swf','*.chm','*.ttf','*.woff','*.eot','*.otf','*.mdf','*.ldf','*.pack',
        '*.zip','*.gz','*.tgz','*.jar','*.nupkg','*.vspscc','*.vsmdi','*.vssscc','*.vsd','*.vscontent','*.vssettings','*.suo',
        '*.dbmdl','*.tdf','*.optdata','*.sigdata'),
    [switch]$CaseSensitive,
    [switch]$List,
    [switch]$NotMatch,
    [switch]$SimpleMatch,
    [switch]$NoRecurse,
    [Alias('Pick')][switch]$ChooseMatches,
    [Parameter(ParameterSetName='Open')][Alias('View')][switch]$Open,
    [Parameter(ParameterSetName='Blame')][Alias('Who')][switch]$Blame
)

function ConvertTo-DateTimeOffset([Parameter(Position=0)][int]$UnixTime,[Parameter(Position=1)][string]$TimeZone)
{
    [DateTimeOffset]::Parse(([DateTime]'1970-01-01Z').AddSeconds($UnixTime).ToString('s')+$TimeZone)
}

$culturetextinfo = (Get-Culture).TextInfo
function Get-LineBlameInfo([Parameter(Position=0)][string]$Path,[Parameter(Position=1)][int]$LineNumber)
{
    pushd "$([IO.Path]::GetDirectoryName($Path))"
    $lineinfo = [Collections.Generic.List[string]]@(git blame -l -p -L "$LineNumber,$LineNumber" -- $Path)
    popd
    ($sha1,$linetext) = ($lineinfo[0],$lineinfo[$lineinfo.Count -1])
    $lineinfo.RemoveAt($lineinfo.Count -1)
    $lineinfo.RemoveAt(0)
    $linehash = @{SHA1 = $sha1; Line = $linetext}
    $lineinfo |
        % {
            ($k,$v)= $_ -split ' ',2
            $linehash.Add(($culturetextinfo.ToTitleCase($k) -replace '-',''),$v)
        }
    $linehash['AuthorTime'] = ConvertTo-DateTimeOffset $linehash['AuthorTime'] $linehash['AuthorTz']
    $linehash.Remove('AuthorTz')
    $linehash['CommitterTime'] = ConvertTo-DateTimeOffset $linehash['CommitterTime'] $linehash['CommitterTz']
    $linehash.Remove('CommitterTz')
    New-Object psobject -Property $linehash
}

# set up splatting
$lsopt = @{Recurse=!$NoRecurse;File=$true}
if($Path) { $lsopt.Path=$Path }
if($Include) { $lsopt.Include=$Include }
if($Exclude) { $lsopt.Exclude=$Exclude }
$ssopt = @{'Pattern'=$Pattern}
if($CaseSensitive) { $ssopt.CaseSensitive=$true }
if($List) { $ssopt.List=$true }
if($NotMatch) { $ssopt.NotMatch=$true }
if($SimpleMatch) { $ssopt.SimpleMatch=$true }
# the filter parameter is much faster than the include parameter
$lookin = if($Filters) { $Filters|% {Get-ChildItem @lsopt -Filter $_} } else { Get-ChildItem @lsopt }
# TODO: Manually handle Include and Exclude for the FullName.
$found = Select-String -Path $lookin @ssopt
if($ChooseMatches) { $found = $found |Out-GridView -Title "Select matches: $Pattern $Filters $Path" -PassThru }
switch($PSCmdlet.ParameterSetName)
{
    Default { $found }
    Open    { $found |Invoke-Item }
    Blame   { $found |% {Get-LineBlameInfo $_.Path $_.LineNumber} }
}
