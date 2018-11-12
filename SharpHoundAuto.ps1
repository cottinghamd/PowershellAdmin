#Requires -version 2.0
#Author: David Cottingham
#This script reads a list of domain names from a file called 'targetdomains.txt'
#It then passes the commands to SharpHound to collect all information and places the results in named subdirectories.

#setup working directories and paths
$working = Get-Location
$sharphoundlocation = "$working\sharphound.exe"
$domainlist = "$working\targetdomains.txt"

#check for administrator privileges
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
	write-host "This script requires administrative privileges which have not been detected. This script will now exit.`r`nPlease start a powershell prompt as an administrator and run the script again. `r`n" -ForegroundColor Yellow
	Pause
	Break
}

#ensure sharphound exists in the current working directory
If (Test-Path -Path $sharphoundlocation -ErrorAction SilentlyContinue)
{
	write-host "Sharphound found $sharphoundlocation"
	
	#ensure a domain list exists in the current working directory
	If (Test-Path -Path $domainlist -ErrorAction SilentlyContinue)
	{
		write-host "Domain list found $domainlist"
		#read in the domain list from the text file and loop through all domains
		Get-Content $domainlist | ForEach-Object{
				write-host "Commencing collection for $_" -ForegroundColor Magenta

				#send commands to sharphound
				Invoke-Expression "./sharphound.exe -d $_ -c All"
				write-host "Collection of $_ complete, files written to $working\" -ForegroundColor Green
		}
	}
	else
	{
		write-host "Domain List Not Found, expected $domainlist" -ForegroundColor Red
		pause
	}
}
else
{
	write-host "Sharphound Not Found, expected $sharphoundlocation" -ForegroundColor Red
	pause
}

