#Requires -version 4.0
#Built mostly from code developed by Emin's blog post which can be found here https://p0w3rsh3ll.wordpress.com/2014/04/05/analysing-files-with-virustotal-com-public-api/
#This code has been updated to monitor for a new volume mount, catch errors / bans from VT and some export & open results changes
#Author: David Cottingham

$scantype = $(Read-Host "Please enter '1' for USB automatic detection or '2' for manual scan")

If ($scantype -eq 1) {

#To ensure multiple events do not get registered, we first call to unregister any exising event called volumeChange. Errors are supressed.
Unregister-Event -SourceIdentifier volumeChange -ErrorAction SilentlyContinue

#Register drive monitoring event and wait
Register-WmiEvent -Class win32_VolumeChangeEvent -SourceIdentifier volumeChange
Write-Host "Waiting for drive attachment" -ForegroundColor Green
$newEvent = Wait-Event -SourceIdentifier volumeChange

#This while statement ensures the program only runs upon USB device insert. It checks for the insert type, if it is any other type it removes and adds the event again and loops.
while ($newEvent.SourceEventArgs.NewEvent.EventType -ne 2){
Remove-Event -SourceIdentifier volumeChange
$newEvent = Wait-Event -SourceIdentifier volumeChange
}

Write-Host "Commencing scan of $($newEvent.SourceEventArgs.NewEvent.DriveName) drive" -ForegroundColor yellow

$Path = $($newEvent.SourceEventArgs.NewEvent.DriveName)
#Remove the WMI event results as we no longer require it. This also prevents old events from firing upon subsequent script runs.
Remove-Event -SourceIdentifier volumeChange

} else {

$path = $(Read-Host "Please enter the drive or path you wish to scan, this can be a drive or directory i.e. 'E:\' or 'E:\Scan\' Directories are searched recursively")

}

$allfiles = @()
# We first clear all errors in the automatic variable
$Error.Clear()
# We capture all files and let error happen silently and being logged into the $error automatic variable
$allfiles = Get-ChildItem -Path $Path -Recurse -Force -Include * -File -ErrorAction SilentlyContinue
 
# Let us know what happen
$Error | Where { $_.CategoryInfo.Reason -eq "PathTooLongException" } | ForEach-Object -Begin{
    Write-Verbose -Message "The following folders contain a file longer than 260 characters"
    # Get-ChildItem : The specified path, file name, or both are too long. 
    # The fully qualified file name must be less than 260 characters, and the directory name must be less than 248 characters.
} -Process {
    $_.CategoryInfo.TargetName
}

Write-Host ("There's a total of {0} files" -f $allfiles.Count) -ForegroundColor Green
 
# Show extensions by occurence
$allfiles | Group -NoElement -Property Extension | Sort -Property Count -Descending
 
Start-Sleep -Seconds 1
 
$totalzip = ($allfiles | Where { $_.Extension }).Count
$filecount = 0
 
# Select only files with a zip extension
$results = @()
$allfiles | Where { $_.Extension } | 
ForEach-Object {
    
    $filecount++
 
    $hash = $res = $page = $checksum = $obj = $outtext = $null
     
    Start-Sleep -Milliseconds (Get-Random -Maximum 750 -Minimum 500)
 
    $hash = (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash
     
    Write-Host ('Searching file {2}/{3} on {0} with sha256 {1}' -f $_.FullName,$hash,$filecount,$totalzip)
     
    # Append a SHA256
    $_ | Add-Member -MemberType NoteProperty -Name SHA256 -Value $hash -Force
 
    # Search virustotal by SHA256
    $res = (Invoke-WebRequest -Uri 'https://www.virustotal.com/en/search/' -Method Post -Body "query=$hash" -MaximumRedirection 0 -ErrorAction SilentlyContinue -UseBasicParsing)
 
    if ($res.StatusCode -eq 302 ) {
        if ($res.Headers.Location) {
            try {
                $page = Invoke-WebRequest -Method GET -Uri $res.Headers.Location -ErrorAction SilentlyContinue -MaximumRedirection 0
            } catch {
                Write-Warning -Message "The request on $($res.Headers.Location) returned $($_.Exception.Message)"
                Write-Host "The server has returned an error, please accept captcha and press any key to continue. If no captcha is deplayed you have been temporarily banned :'(" -foregroundcolor Yellow
                start $res.Headers.Location
            Pause
            }
            if ($page.Headers.Location -notmatch "file/not/found/") {
                try {
                    $obj = New-Object -TypeName PSObject
                    $outtext = ($page.AllElements | Where { ($_.TagName -eq 'TBODY') -and ($_.outerHTML -match "$hash") -and ($_.outerText -match "Detection\sratio") }).OuterText
                    if ($outtext) {
                        $outtext -split "`n" |  ForEach-Object {
                            if ($_ -match ":") {
                            $obj | Add-Member -MemberType NoteProperty -Name ($_ -split ":")[0] -Value (-join($_ -split ":" )[1..($_ -split ":" ).count]) -Force
                            } else {
                                Write-Warning -Message "Mismatch with ':'"
                                $_
                            }
                        }
                        # Analysis tab
                        $count = 0
                        $analysisar = @()
                        $AVName = $DetectionDate = $DetectionRate = $null
    
                        ([regex]'<TD\sclass=("?)ltr(>|\stext\-green"><I\stitle="|\stext-red">)(?<ID>.*)("\sclass=icon\-ok\-sign\sdata\-toggle="tooltip"></I></TD>|\s</TD>)').Matches(
                        $page.AllElements.FindById('antivirus-results').outerHTML) | ForEach-Object -Process {
                            $count++
                            switch ((@($_.Groups))[-1]) {
                                {$_ -match '\d{8}'} { $DetectionDate = $_ ; break}
                                {$_ -match '(^\-$|^File\snot\sdetected$)'}{ $DetectionRate = '-' ; break }
                                {$_ -match '.*'} {
                                    if ($count -eq 1) {
                                        $AVName = $_
                                    } else {
                                        $DetectionRate = $_
                                    }
                                    ; break
                                }
                            }
                            if ($count -eq 3) {
                                $count = 0
                                $analysisar += New-Object -TypeName PSObject -Property @{
                                    Update = $DetectionDate
                                    Result = $DetectionRate
                                    Antivirus = $AVName
                                }
                            }
                        }
                        $obj | Add-Member -MemberType NoteProperty -Name Analysis -Value $analysisar -Force
                        $obj
                        $_ | Add-Member -MemberType NoteProperty -Name VTResults -Value $obj -Force
                    } else {
                        # Write-Warning -Message "$outtext # is because the file has probably been never submitted"
                        # it shouldn't happen but... who knows
                        $_ | Add-Member -MemberType NoteProperty -Name VTResults -Value ([string]::Empty) -Force
                    }
                } catch {
                    $_
                }
            } else {
                Write-Warning -Message "the file was not found"
                $_ | Add-Member -MemberType NoteProperty -Name VTResults -Value "Unknown by VT" -Force
            }
        } else {
            Write-Warning -Message "the location in the header is empty"
            $_ | Add-Member -MemberType NoteProperty -Name VTResults -Value "Header empty issue" -Force
        }
    } else {
        Write-Warning -Message "the page returned a $($res.StatusCode) status code"
        $_ | Add-Member -MemberType NoteProperty -Name VTResults -Value "Status code issue" -Force
    }
    $results += $_
}
 
Write-Host ("There's a total of {0} results" -f $results.Count) -ForegroundColor Magenta
 
$unknowncount = ("{0}" -f (
    $results | Where 'VTResults' -eq "Unknown by VT").Count
)

Write-Host "There's a total of $unknowncount unknown files" -ForegroundColor Magenta
 
# Export results to CSV
$outputpath = "$($env:USERPROFILE)\Documents\VT.analysis.$(get-date -f yyyy-MM-dd-hh-mm).csv"
 
# First unknown files
($results | Where 'VTResults' -eq "Unknown by VT") | 
Select Name,FullName,SHA256,
    @{l='Ratio';e={'Unknown by VT'}},
    @{l='MalwareName';e={[string]::Empty}} | 
Export-Csv -Path "$outputpath" -Encoding UTF8  -NoTypeInformation -Delimiter ","
 
# Then export files that are identified as malware
$knowncount = ("{0}" -f (
    $results | Where 'VTResults' -notin @("Unknown by VT","Header empty issue","Status code issue")).Count
)

Write-Host "There's a total of $knowncount known files" -ForegroundColor Magenta

($results | Where 'VTResults' -notin @("Unknown by VT","Header empty issue","Status code issue")) |
Select Name,FullName,SHA256,
    @{l='Ratio';e={
        $_.VTResults.'Detection Ratio' -replace '\s',''
    }},
    @{l='MalwareName';e={
        ($_.VTResults.Analysis | Where { $_.Result -notmatch "^\-$"}).Result -as [string[]]
    }} | Export-Csv -Path $outputpath -Encoding UTF8 -Append -NoTypeInformation -Delimiter ","

If ($knowncount -ne 0) {

Invoke-Item $outputpath

Write-Host "Launching results file $outputpath" -ForegroundColor Green

} else {

Write-Host "There were no detections, please note: there were $unknowncount unknown files. Further detailed results can be found in $outputpath" -ForegroundColor Green

}