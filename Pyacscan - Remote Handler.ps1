<#	
	.NOTES
	===========================================================================
	 Created by:   	David Cottingham
	 Purpose:       This powershell script facilitates remote computer scanning using the ACSC Pyacscan.exe utility (this utility is local scanning only).
                    You can download this utility here: https://cyber.gov.au/government/news/parliament-house-network-compromise/

                    This script requires PowerShell remoting, remote administrative access and SMB share access to the target C drive admin share.
                    
                    Scan results will be returned to the local scan directory. I hope it helps :)  	
	===========================================================================
#>

Param ($MaxThreads = 50,
	$SleepTimer = 500,
	$MaxWaitAtEnd = 168000)

#check for administrator privileges
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
	write-host "This script requires administrative privileges which have not been detected. This script will now exit.`r`nPlease start a powershell prompt as an administrator and run the script again. `r`n" -ForegroundColor Yellow
	Pause
	Break
}

$ComputerList = $(Read-Host "Please enter the path to a list of computers you wish to scan, for example C:\Results\DetailedResults.txt")
If (Test-Path -Path $ComputerList -ErrorAction SilentlyContinue)
{
    #Do nothing
}
else
{
	write-host "ComputerList Not Found, please check the path you entered" -ForegroundColor Red
	pause
    break
}

$pyacscanpath = $(Read-Host "Please enter the path to pyacscan.exe, for example C:\temp\pyacscan.exe")
If (Test-Path -Path $pyacscanpath -ErrorAction SilentlyContinue)
{
    #Do nothing
}
else
{
	write-host "Pyacscan.exe not found, please check the path you entered" -ForegroundColor Red
	pause
    break
}

$ResultsPath = $(Read-Host "Please enter the directory you want to output scan results to, for example C:\temp\results (the directory must exist! no trailing \ character required)")
If (Test-Path -Path $ResultsPath -ErrorAction SilentlyContinue)
{
    #Do nothing
}
else
{
	write-host "The output directory does not exist, please check the path you entered" -ForegroundColor Red
	pause
    break
}

Write-Host "Note, this script uses PowerShell remoting, requires remote administrative access and SMB read-write to the C drive admin share." -foregroundcolor Yellow

$servers = Get-Content $ComputerList | Sort-Object | Get-Unique
$numcomps = $servers.Count
write-host "There are $numcomps endpoints queued for scanning" -foregroundcolor "green"

Write-Host "Killing existing jobs..."
Get-Job | Remove-Job -Force
Write-Host "Done"

write-host "Ready to scan?" -foregroundcolor Yellow
Pause


$sb = {
	param ([string]$server,[string]$pyacscanpath,[string]$ResultsPath)
	
	If (!(Test-Connection -comp $server -count 1 -ea 0 -quiet))
	{
		
		Write-Warning -Message "Could not ping $server assuming offline, skipping"
		Write-Output "$server offline" | Out-File "$ResultsPath\$server.couldnotping.txt"
	}
	else
	{
		
		try { Copy-Item -Path $pyacscanpath -Destination "\\$server\c$\pyacscan.exe" -ErrorAction Stop}
		catch { "Error Copying File To Remote Location, Likely Access Denied" | Out-File  "$ResultsPath\$server.accessdenied.txt"
			break
		}
		
		Invoke-Command -ComputerName $server -ScriptBlock { & cmd.exe /c "cd c:\ && pyacscan.exe" }
		
		$file = "\\$server\c$\scan.txt"
		
		Get-Content $file | Out-File "$ResultsPath\$server.txt"
		
		Remove-Item -Path "\\$server\c$\pyacscan.exe"
		Remove-Item -Path "\\$server\c$\scan.txt"
	}
}

$i = 0

ForEach ($server in $servers)
{
	While ($(Get-Job -state running).count -ge $MaxThreads)
	{
		Write-Progress  "Scanning In Progress"
		write-output "$i threads created - $($(Get-Job -state running).count) threads open, waiting for threads to close before starting more"
		write-output "$($i / $servers.count * 100) $("% Complete")"
		Start-Sleep -Milliseconds $SleepTimer
	}
	
	#"Starting job - $Computer"
	$i++
	Start-Job -ScriptBlock $sb -ArgumentList $server, $pyacscanpath, $ResultsPath | Out-Null
	Write-Progress  "Scanning In Progress"
	write-output CurrentOperation "$i threads created - $($(Get-Job -state running).count) threads open, scanning $server"
	write-output "$($i / $servers.count * 100) $("% Complete")"
	
}

$Complete = Get-date

While ($(Get-Job -State Running).count -gt 0)
{
	$ComputersStillRunning = ""
	ForEach ($server  in $(Get-Job -state running)) { $ComputersStillRunning += ", $($server.name)" }
	$ComputersStillRunning = $ComputersStillRunning.Substring(2)
	Write-Progress  "Nearly Done, Waiting For Last Jobs To Finish"
	write-output  "$($(Get-Job -State Running).count) threads remaining"
	write-output  "$ComputersStillRunning"
	write-output  "$($(Get-Job -State Completed).count / $(Get-Job).count * 100)$("% Complete")"
	If ($(New-TimeSpan $Complete $(Get-Date)).totalseconds -ge $MaxWaitAtEnd) { "Killing all jobs still running . . ."; Get-Job -State Running | Remove-Job -Force }
	Start-Sleep -Milliseconds $SleepTimer
}

"Reading all jobs"

#This section reads the results from jobs in the script block

ForEach ($Job in Get-Job)
{
	Receive-Job $Job
}
