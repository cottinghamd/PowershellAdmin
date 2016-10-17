#This is a really nasty script to check for the presence of Macros within certain types of office documents
#The documents are opened in a background window (i know) however active code is disabled and then the HASVBProject element is checked
#This script asks for a path you wish to scan. Thought it might come in handy for some, or at least prompt some ideas of a (albeit bad) way to handle this
#Script only looks for XML based Office file types
#Author: David Cottingham

$path = $(Read-Host "Please enter the drive or path you wish to look for Office documents, this can be a drive or directory i.e. 'E:\' or 'E:\Scan\' Directories are searched recursively")

$xl = New-Object -ComObject Excel.Application
$xl.AutomationSecurity = 'msoAutomationSecurityForceDisable'
$wrd = New-Object -ComObject Word.Application
$wrd.AutomationSecurity = 'msoAutomationSecurityForceDisable'
$ppt = New-Object -ComObject Powerpoint.Application
$ppt.AutomationSecurity = 'msoAutomationSecurityForceDisable'

$allfiles = Get-ChildItem -Path $path -Recurse -Force -Include *.docx,*.pptx,*.xlsx,*.docm,*.pptm,*.xlsm -File -Exclude *~$* -ErrorAction SilentlyContinue
$allfiles | Group -NoElement -Property Extension | Sort -Property Count -Descending

$allfiles | Where { $_.Extension } | 


ForEach-Object {

$document = ('{0}' -f $_.FullName)

    if ($_.Extension -match '.xls?'){

        $workbook = $xl.Workbooks.Open(("$document"),$false, $true)

            if ($workbook.HASVBProject -eq 'true') {
                Write-Host ("$document contains VBA Macro Code")
                $documentmacro++
            }
    }
            
            ElseIf ($_.Extension -match '.doc?'){

                        $workbook = $wrd.Documents.Open(("$document"),$false, $true)

                            if ($workbook.HASVBProject -eq 'true') {
                                Write-Host ("$document contains VBA Macro Code")
                                $documentmacro++
                            }
            }
                    ElseIf ($_.Extension -match '.ppt?'){

                            $workbook = $ppt.Presentations.Open(("$document"),[Microsoft.Office.Core.MsoTriState]::msoFalse,[Microsoft.Office.Core.MsoTriState]::msoFalse,[Microsoft.Office.Core.MsoTriState]::msoFalse)

                                if ($workbook.HASVBProject -eq 'true') {
                                    Write-Host ("$document contains VBA Macro Code")
                                    $documentmacro++

                                    }
                    }
}
                                    