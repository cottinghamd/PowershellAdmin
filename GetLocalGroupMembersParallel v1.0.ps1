	<#
	.SYNOPSIS
	This script retrieves the BUILTIN user groups from a computer and their memberships. This allows you to determine which domain groups may have specific rights over a remote machine.

	.DESCRIPTION
        This script remotely connects to computers and retrieves the BUILTIN user memberships. It also outputs 'de-duplicated' administrative group information allowing you to determine which domain groups or users have administrative rights on machines.

        This script accepts computer names from an input text file, with each computername on a new line (the script does automatic deduplication of computernames).

        This script will output the results to two user defined CSV Files:
            Detailed Results CSV: Contains the full group information and computer information for analysis;
            Administrative Group Results CSV: Contains de-duplicated administrative group information, this file may need to be cross referenced with Detailed Results CSV for specific computer information.

	    This script has been made using code portions from the following scripts:
        https://gallery.technet.microsoft.com/scriptcenter/Get-LocalGroupMembers-b714517d Piotr Lewandowski
        http://www.get-blog.com/?p=22 Ryan Witschger

	.NOTES
	    Version      			: 1.0
	    Rights Required			: Local admin rights over remote computer
	    Author(s)    			: David Cottingham (david@airlockdigital.com)
	    Disclaimer   			: Please test every script before running it in production!


	.INPUTS
		None. You cannot pipe objects to this script.

	#Requires -Version 3.0
	#>

Param($ComputerList = $(Read-Host "Enter the Location of the target computerlist, this must be text formatted with one computer name per line"),
    $OutputResults = $(Read-Host "Enter the file path for detailed results to be written e.g. C:\Results\DetailedResults.csv"),
    $AdminGroups = $(Read-Host "Enter the file path for Administrative Group Results (deduplicated) to be written e.g. C:\Result\AdminResults.csv"),
    $GroupName = $(Read-Host "Enter the name of the group you wish to scan for e.g Administrators (leave blank and press enter for all groups)"),
    $MaxThreads = 50,
    $SleepTimer = 500,
    $MaxWaitAtEnd = 600,
    $OutputType = "Text")

#This block checks that the computer list exists and the user has not made a typo

$TestPathResult = Test-Path $ComputerList
    
If ($TestPathResult -notmatch 'True')
{
     Throw 'The entered file path is not valid. Please enter a valid file path to a .txt file containing a list of computers you want to scan e.g. C:\toscan\computers.txt'
}

#This block loads the computer list, sorts it and only outputs unique values. It then counts the number of computers for scanning and displays this to the user.

$servers = Get-Content $ComputerList | Sort-Object | Get-Unique
$numcomps = $servers.Count
write-host "There are $numcomps endpoints queued for scanning" -foregroundcolor "green"

#This makes sure that there are no existing powershell jobs running before commencing the script

"Killing existing jobs..."
Get-Job | Remove-Job -Force
"Done"

                       
#This calls the pause function and waits for the user to press a key before continuing the script.
write-host "Ready to scan?" -foregroundcolor Yellow
Pause

$sb = {
 param ([string] $server, $GroupName)

If(!(Test-Connection -comp $server -count 1 -ea 0 -quiet))

{

Write-Warning -Message "Could not ping $server assuming offline, skipping"

}

ELSE

{
    $finalresult = @()
    $computer = [ADSI]"WinNT://$server"

    if (!($groupName))
    {
    $Groups = $computer.psbase.Children | Where {$_.psbase.schemaClassName -eq "group"} | select -expand name
    }
    else
    {
    $groups = $groupName
    }
    $CurrentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().GetDirectoryEntry() | select name,objectsid
    $domain = $currentdomain.name
    $SID=$CurrentDomain.objectsid
    $DomainSID = (New-Object System.Security.Principal.SecurityIdentifier($sid[0], 0)).value


    foreach ($group in $groups)
    {
    $gmembers = $null
    $LocalGroup = [ADSI]("WinNT://$server/$group,group")


    $GMembers = $LocalGroup.psbase.invoke("Members")
    $GMemberProps = @{Server="$server";"Local Group"=$group;Name="";Type="";ADSPath="";Domain="";SID=""}
    $MemberResult = @()


        if ($gmembers)
        {
        foreach ($gmember in $gmembers)
            {
            $membertable = new-object psobject -Property $GMemberProps
            $name = $gmember.GetType().InvokeMember("Name",'GetProperty', $null, $gmember, $null)
            $sid = $gmember.GetType().InvokeMember("objectsid",'GetProperty', $null, $gmember, $null)
            $UserSid = New-Object System.Security.Principal.SecurityIdentifier($sid, 0)
            $class = $gmember.GetType().InvokeMember("Class",'GetProperty', $null, $gmember, $null)
            $ads = $gmember.GetType().InvokeMember("adspath",'GetProperty', $null, $gmember, $null)
            $MemberTable.name= "$name"
            $MemberTable.type= "$class"
            $MemberTable.adspath="$ads"
            $membertable.sid=$usersid.value


            if ($userSID -like "$domainsid*")
                {
                $MemberTable.domain = "$domain"
                }

            $MemberResult += $MemberTable
            }

         }
         $finalresult += $MemberResult 
    }
    $finalresult | select server,"local group",name,type,domain,sid
}
}


$i = 0

ForEach ($server in $servers){
    While ($(Get-Job -state running).count -ge $MaxThreads){
        Write-Progress  "Scanning In Progress" 
                        write-output "$i threads created - $($(Get-Job -state running).count) threads open, waiting for threads to close before starting more" 
                        write-output "$($i / $servers.count * 100) $("% Complete")"
        Start-Sleep -Milliseconds $SleepTimer
    }

    #"Starting job - $Computer"
    $i++
    Start-Job -ScriptBlock $sb -ArgumentList $server | Out-Null
    Write-Progress  "Scanning In Progress"  
                 write-output CurrentOperation "$i threads created - $($(Get-Job -state running).count) threads open, scanning $server"
                 write-output "$($i / $servers.count * 100) $("% Complete")"
    
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

#This section reads the results from jobs in the script block

ForEach($Job in Get-Job)
{
   Receive-Job $Job | Export-CSV -Path $OutputResults -Append -NoTypeInformation -Force
}

#This section parses the job results and generates the Administrative Group Results CSV
$ParseCSV = Import-CSV $OutputResults
Add-Content $AdminGroups '"Count","Name","User/Group","Domain/Local(Blank)"'
$ParseCSV |where-object {$_.'Local Group' -eq "Administrators"} | Select-Object -Property Name,Type,Domain|Group-Object -Property Name,Type,Domain -NoElement | Select-Object Count,Name |Export-Csv $AdminGroups -NoTypeInformation -Append -Force
(Get-Content $AdminGroups).replace(', ', '","')| Set-Content $AdminGroups

write-host "Please see $OutputResults for detailed information" -foregroundcolor Yellow
write-host "Please see $AdminGroups for unique groups or users that have administrative access (assumes Administrators was searched for)" -foregroundcolor Green

function PauseFinal

{
   Read-Host 'Scanning Complete, press any key to exit' | Out-Null
}

PauseFinal
