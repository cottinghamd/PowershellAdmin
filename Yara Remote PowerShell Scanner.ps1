<#	
	.NOTES
	===========================================================================
	 Created by:   	David Cottingham
	 Purpose:       This powershell script facilitates remote computer scanning using yara.exe and a set of specified yara rules.
                    You can download the latest version of yara here: https://github.com/VirusTotal/yara/releases

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

$yarascanpath = $(Read-Host "Please enter the path to the main yara executable, for example C:\temp\yara.exe")
If (Test-Path -Path $yarascanpath -ErrorAction SilentlyContinue)
{
    #Do nothing
}
else
{
	write-host "yara binary not found, please check the path you entered" -ForegroundColor Red
	pause
    break
}

$yaraiocpath = $(Read-Host "Please enter the path to the yara ioc file you wish to use, for example C:\temp\toscan.yar")
If (Test-Path -Path $yaraiocpath -ErrorAction SilentlyContinue)
{
    #Do nothing
}
else
{
	write-host "yara ioc file not found, please check the path you entered" -ForegroundColor Red
	pause
    break
}

$vcruntime = $(Read-Host "Please enter the path to the vcruntime140.dll (this adds support for hosts that don't have C++ Runtime installed), for example C:\Windows\System32\vcruntime140.dll")
If (Test-Path -Path $vcruntime -ErrorAction SilentlyContinue)
{
    #Do nothing
}
else
{
	write-host "vcruntime140.dll not found, please check the path you entered" -ForegroundColor Red
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
	param ([string]$server,[string]$yarascanpath,[string]$yaraiocpath,[string]$vcruntime,[string]$ResultsPath)
	
	If (!(Test-Connection -comp $server -count 1 -ea 0 -quiet))
	{
		
		Write-Warning -Message "Could not ping $server assuming offline, skipping"
		Write-Output "$server offline" | Out-File "$ResultsPath\$server.couldnotping.txt"
	}
	else
	{
		
		try { Copy-Item -Path $yarascanpath -Destination "\\$server\c$\yara.exe" -ErrorAction Stop}
		catch { "Error Copying File To Remote Location, Likely Access Denied" | Out-File  "$ResultsPath\$server.accessdenied.txt"
			break
		}

		try { Copy-Item -Path $yaraiocpath -Destination "\\$server\c$\toscan.yar" -ErrorAction Stop}
		catch { "Error Copying File To Remote Location, Likely Access Denied" | Out-File  "$ResultsPath\$server.accessdenied.txt"
			break
		}

		try { Copy-Item -Path $vcruntime -Destination "\\$server\c$\vcruntime140.dll" -ErrorAction Stop}
		catch { "Error Copying vcruntime140.dll To Remote Location, Likely Access Denied" | Out-File  "$ResultsPath\$server.accessdenied.txt"
			break
		}
		
        try { $diskstoscan = Get-WmiObject Win32_Logicaldisk -Namespace "root\cimv2" -Computer $server | where {($_.DriveType -match '3')} | Select-Object DeviceID}
        		catch { "Error Quering Remote drives via WMI, Likely Access Denied" | Out-File  "$ResultsPath\$server.wmifailure.txt"
			break
		}

        ForEach ($disk in $diskstoscan)
        {
            $disk = $disk.DeviceID + "\"
		    Invoke-Command -ComputerName $server -ScriptBlock {param($diskinblock) & cmd.exe /c "cd c:\ && yara.exe --recursive --threads=1 C:\toscan.yar $diskinblock >> scan.txt" } -ArgumentList $disk
        }

		$file = "\\$server\c$\scan.txt"
		
		Get-Content $file | Out-File "$ResultsPath\$server.txt"
		
		Remove-Item -Path "\\$server\c$\yara.exe"
		Remove-Item -Path "\\$server\c$\toscan.yar"
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
	Start-Job -ScriptBlock $sb -ArgumentList $server, $yarascanpath, $yaraiocpath, $vcruntime, $ResultsPath | Out-Null
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