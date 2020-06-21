<#
.Synopsis
	Returns true if the specified file is locked.

.Parameter Path
	A path to a file to test.

.Inputs
	Object with System.String property named Path containing the path to a file to test.

.Outputs
	System.Boolean indicating whether the file is locked.
#>

#Requires -Version 3
[CmdletBinding()][OutputType([bool])] Param(
[Parameter(Position=0,Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
[Alias('FullName')][string] $Path
)
Begin
{
    try{[void][RebootFileAction]}catch{Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class RebootFileAction
{
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    private static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);
    const int MOVEFILE_DELAY_UNTIL_REBOOT = 0x4;
    static public void Delete(string filename)
    {
        if(!MoveFileEx(filename,"",MOVEFILE_DELAY_UNTIL_REBOOT))
        { throw new InvalidOperationException(String.Format("Unable to mark {0} for deletion at reboot.",filename)); }
    }
}
'@}
}
Process
{
	#TODO: ...
}
