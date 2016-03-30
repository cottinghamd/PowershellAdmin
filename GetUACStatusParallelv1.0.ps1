	<#
	.SYNOPSIS
	   	This script gets the current status of User Account Control (UAC) on a computer

	.DESCRIPTION
        This script runs a UAC registry check across numerous computers using parallel jobs. By default the job threads are fixed at 50, change $MaxThreads to increase.

        This script accepts computer names from an input text file, with each computername on a new line (the script does automatic deduplication of computernames).

        This script will output the results do a defined CSV formatted file as prompted.

	    This script has been made using code portions from the following scripts:
        http://www.ehloworld.com/1026 Pat Richard (pat@innervation.com)
        http://www.get-blog.com/?p=22 Ryan Witschger

	.NOTES
	    Version      			: 1.0
	    Rights Required			: Local admin over remote computer, remote registry service required
	    Author(s)    			: David Cottingham (david@airlockdigital.com)
	    Disclaimer   			: Please test every script before running it in production!


	.INPUTS
		None. You cannot pipe objects to this script.

	#Requires -Version 3.0
	#>

Param($ComputerList = $(Read-Host "Enter the Location of the target computerlist, this must be text formatted with one computer name per line"),
    $OutputResults = $(Read-Host "Enter the desired location for results to be written e.g. C:\Results\UACResults.csv"),
    $MaxThreads = 50,
    $SleepTimer = 500,
    $MaxWaitAtEnd = 600,
    $OutputType = "Text")

#This block checks that the computer list exists and the user has not made a typo

$TestPathResult = Test-Path $ComputerList
    
If ($TestPathResult -notmatch 'True')
{
     Write-Warning "The entered computer list file path '$ComputerList' is not valid. Please enter a valid file path to a .txt file containing a list of computers you want to scan e.g. C:\toscan\computers.txt"
}

#This block loads the computer list, sorts it and only outputs unique values. It then counts the number of computers for scanning and displays this to the user.

$Computers = Get-Content $ComputerList | Sort-Object | Get-Unique
$numcomps = $computers.Count
write-host "There are $numcomps endpoints queued for scanning" -foregroundcolor "green"

#This makes sure that there are no existing powershell jobs running before commencing the script

"Killing existing jobs..."
Get-Job | Remove-Job -Force
"Done"

                       
#This calls the pause function and waits for the user to press a key before continuing the script.
write-host "Ready to scan?" -foregroundcolor Yellow
Pause

$sb = {
 param ([string] $Computer)

If(!(Test-Connection -comp $Computer -count 1 -ea 0 -quiet))

{
    $Joboutput = "$Computer,Can't Ping (Offline)"
    return $Joboutput
}

ELSE

{
	[string]$RegistryValue = "EnableLUA"
	[string]$RegistryPath = "Software\Microsoft\Windows\CurrentVersion\Policies\System"
	[bool]$UACStatus = $false
    $error.clear()

    Try
    {
	    $OpenRegistry = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$Computer)
    }
    Catch
        {
            $Joboutput = "$Computer,Unable to access the Remote Registry"
            return $Joboutput
        }

    If(!$error)
        {
	        $Subkey = $OpenRegistry.OpenSubKey($RegistryPath,$false)
	        $Subkey.ToString() | Out-Null
	        $UACStatus = ($Subkey.GetValue($RegistryValue) -eq 1)
            $Joboutput = "$Computer,$UACStatus"
            return $Joboutput
        }

}
}

$i = 0

ForEach ($Computer in $Computers){
    While ($(Get-Job -state running).count -ge $MaxThreads){
        Write-Progress  "Scanning In Progress" 
                        write-output "$i threads created - $($(Get-Job -state running).count) threads open, waiting for threads to close before starting more" 
                        write-output "$($i / $Computers.count * 100) $("% Complete")"
        Start-Sleep -Milliseconds $SleepTimer
    }

    #"Starting job - $Computer"
    $i++
    Start-Job -ScriptBlock $sb -ArgumentList $computer | Out-Null
    Write-Progress  "Scanning In Progress"  
                 write-output CurrentOperation "$i threads created - $($(Get-Job -state running).count) threads open, scanning $computer"
                 write-output "$($i / $Computers.count * 100) $("% Complete")"
    
}

$Complete = Get-date

While ($(Get-Job -State Running).count -gt 0){
    $ComputersStillRunning = ""
    ForEach ($System  in $(Get-Job -state running)){$ComputersStillRunning += ", $($System.name)"}
    $ComputersStillRunning = $ComputersStillRunning.Substring(2)
    Write-Progress  "Nearly Done, Waiting For Last Jobs To Finish" 
                    write-output  "$($(Get-Job -State Running).count) threads remaining" 
                    write-output  "$ComputersStillRunning" 
                    write-output  "$($(Get-Job -State Completed).count / $(Get-Job).count * 100 )$("% Complete")"
    If ($(New-TimeSpan $Complete $(Get-Date)).totalseconds -ge $MaxWaitAtEnd){"Killing all jobs still running . . .";Get-Job -State Running | Remove-Job -Force}
    Start-Sleep -Milliseconds $SleepTimer
}

"Reading all jobs"

#This section reads the results from jobs in the script block, writes the file header.
Write-output "#Computer,#UACEnabled" | Out-File -filepath $OutputResults

ForEach($Job in Get-Job)
{
   Receive-Job $Job | Out-File -filepath $OutputResults -Append
}

write-host "Please see $OutputResults for your data" -foregroundcolor "yellow"

function PauseFinal

{
   Read-Host 'Scanning Complete, press any key to exit' | Out-Null
}

PauseFinal