<#	
	.NOTES
	===========================================================================
	 Created by:   	David Cottingham
	 Purpose:       This powershell script facilitates remote installation of the velociraptor MSI.
                    You can download the latest version of velociraptor
                     here: https://github.com/Velocidex/velociraptor/releases

                    This script requires PowerShell remoting, remote administrative access and SMB share access to the target C drive admin share.
                    
                    Scan results will be returned to the local scan directory. I hope it helps :)  	
	===========================================================================
#>

Param ($MaxThreads = 5,
	$SleepTimer = 500,
	$MaxWaitAtEnd = 168000)

#check for administrator privileges
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
	write-host "This script requires administrative privileges which have not been detected. This script will now exit.`r`nPlease start a powershell prompt as an administrator and run the script again. `r`n" -ForegroundColor Yellow
	Pause
	Break
}

$msipath = $(Read-Host "Please enter the path to the main velociraptor MSI installer, for example C:\temp\velociraptor.msi")
If (Test-Path -Path $msipath -ErrorAction SilentlyContinue)
{
    #Do nothing
}
else
{
	write-host "velociraptor msi not found, please check the path you entered" -ForegroundColor Red
	pause
    break
}

$ComputerList = $(Read-Host "Please enter the path to a list of computers you wish to isntall velociraptor on, for example C:\Results\toinstall.txt")
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


$workingdir = Split-Path -Path $msipath
write-host "`nChecking if a velociraptor client configuration file is already in the specified msi directory"

If ((Get-ChildItem -Path $workingdir -Filter Velociraptor.config.yaml -File -Name) -ne $null)
{
    $vconfig = Get-ChildItem -Path $workingdir -Filter Velociraptor.config.yaml  -File -Name
 
        write-host "Velociraptor configuration file found, using $vconfig"

}
else
{
    $vconfig = $(Read-Host "No file found, please enter the path to the velociraptor configuration file you wish to use, for example C:\temp\velociraptor.config.yaml")
    If (Test-Path -Path $vconfig -ErrorAction SilentlyContinue)
    {
        #Do nothing
    }
    else
    {
	    write-host "velociraptor configuration file not found, please check the path you entered" -ForegroundColor Red
	    pause
        break
    }
}

$ResultsPath = $(Read-Host "`nPlease enter the directory you want to output scan results to, for example C:\temp\results (the directory must exist! no trailing \ character required)")
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
	param ([string]$server,[string]$msipath,[string]$vconfig,[string]$ResultsPath)
	
	If (!(Test-Connection -comp $server -count 1 -ea 0 -quiet))
	{
		
		Write-Warning -Message "Could not ping $server assuming offline, skipping"
		Write-Output "$server offline" | Out-File "$ResultsPath\$server.couldnotping.txt"
	}
	else
	{
		
		try { Copy-Item -Path $msipath -Destination "\\$server\c$\velociraptor.msi" -ErrorAction Stop}
		catch { "Error Copying File To Remote Location, Likely Access Denied" | Out-File  "$ResultsPath\$server.accessdenied.txt"
			break
		}


        try {  wmic product call install true,"" , "velociraptor.msi"}
        		catch { "Error installing MSI" | Out-File  "$ResultsPath\$server.msiinstallfailure.txt"
			break
		}



        try { Copy-Item -Path $vconfig -Destination "\\$server\c$\Program Files\Velociraptor\Velociraptor.config.yaml" -ErrorAction Stop}
		catch { "Error Copying velociraptor config file, agent will need manual intervention to work" | Out-File  "$ResultsPath\$server.configcopyfail.txt"
			break
		}


		
		Write-Output "Installed ok" | Out-File "$ResultsPath\$server.txt"
		
		Remove-Item -Path "\\$server\c$\velociraptor.msi"
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
	Start-Job -ScriptBlock $sb -ArgumentList $server, $msipath, $vconfig, $ResultsPath | Out-Null
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