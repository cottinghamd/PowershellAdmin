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
 
        #if a subdirectory with the domain name already exists, skip scanning the domain
        If (Test-Path -Path "$working\$_" -ErrorAction SilentlyContinue)
        {
            write-host "Skipping scan of $_ as results directory already exists" -ForegroundColor Yellow
        }
        else
        {
            write-host "Commencing collection for $_" -ForegroundColor Magenta
            #create a subdirectory with the domains name
            New-Item -Path "$working\$_" -ItemType directory |Out-Null
            #test that the folder exists before proceeding
                If (Test-Path -Path "$working\$_" -ErrorAction SilentlyContinue)
                {
                    #send commands to sharphound
                    write-host "$sharphoundlocation -d $_"
                    Invoke-Expression "$sharphoundlocation -d $_ -f `"$working\$_`""
                    Invoke-Expression "$sharphoundlocation -d $_ -c ObjectProps -f `"$working\$_`""
                    Invoke-Expression "$sharphoundlocation -d $_ -c ACL -f `"$working\$_`""
                    write-host "Collection of $_ complete, files written to $working\$_\" -ForegroundColor Green
                }
                else
                {
                    write-host "Directory creation for $_ failed"
                }
 
         }
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