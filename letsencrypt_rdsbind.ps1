#
# For use as a Post-request PS script with Certiy the Web's client.
#

Set-Alias ps64 "$env:windir\sysnative\WindowsPowerShell\v1.0\powershell.exe"
function DumbDebugToConsole($msg) { Write-Output "DBG :: $msg" } # totally necessary..

[scriptblock]$main_scriptblock = {
	# This SB gets executed later on 
	
	function DumbDebugToConsole($msg) { Write-Output "DBG :: $msg" }

    Import-Module RemoteDesktop
	
    ## Init
	
	# I tried using the variable they pass a param when starting, was giving issues.. so i'm rolling my own.
	$pfx_dir = "C:\ProgramData\ACMESharp\sysVault\99-ASSET"
    $this_pfxpath = (Get-ChildItem $pfx_dir | Sort-Object CreationTime -Descending | Select -Index 0).FullName
    $this_thumbprint = (Get-PfxCertificate $this_pfxpath).Thumbprint
	DumbDebugToConsole "CertPath: $this_pfxpath"
	DumbDebugToConsole "Thumbprint: $this_thumbprint"
	
    ## Main

    # Apply to RDS Roles
	[int]$successCount = 0
    Get-RDCertificate | ForEach-Object { 
        $role = "$($_.Role)"
        Write-Output "Procesing role: $role"

        # dont reapply
        if ($_.thumbprint -ne $this_thumbprint) {
            try {
                Set-RDCertificate -Role $role -ImportPath "$this_pfxpath" -Force -Verbose -ErrorAction Stop
                Write-Output " > Success"
				$successCount++
            }
            catch {
                Write-Output " > Error: $error[0]"
            }
        }
        else {
            Write-Warning "Certificate is already applied"
        }
    }

	# Restart RDS
	if ($successCount -gt 0) {
		Get-Service "TS*" | Restart-Service
	}
	
}

if ([Environment]::Is64BitProcess) {
	DumbDebugToConsole "Process is x64 already"
	Invoke-Command -ScriptBlock $main_scriptblock
}

else {
	DumbDebugToConsole "Translating to PS x64"
	ps64 -Command $main_scriptblock
}