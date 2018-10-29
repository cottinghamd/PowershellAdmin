#Get the current working directory
$WorkingDir = Get-Location

#Check to see if the domain list is located in the current working directory
If (Test-Path -path "$WorkingDir\domainlist.csv" -ErrorAction SilentlyContinue)
{
	$SitestoScan = Import-CSV -Path "$WorkingDir\domainlist.csv"
}
else
{
	$SiteCSV = Read-Host "Please type the full path to the CSV containing the sites you wish to scan. e.g. C:\domainlist.csv (Note: This CSV must have a header row called Sites)"
	$SitestoScan = Import-CSV -Path $SiteCSV
}

#Abort the script is a valid domain list is unable to be found or populated
If ($SitestoScan.Sites -eq $null)
{
	Write-Output "The CSV is not valid or has been incorrectly formatted. Please ensure the CSV has a header row of Sites and each site you want to scan on a new line in the file"
	Pause
	break
}


#The main function to perform SPF Validation
function Validate-SPF ($domain)
{
	#null out the variables in the event this is run in powershell ISE
	$record = $null
	$y = $null
	$res = $null
	
	#Call the dns function to check for SPF Records
	$DNSResult = Get-DNS $domain
	$y = $DNSResult | where { $_.strings -like "*spf1*" } | select name, strings, Type
	
	
	#Create an array called 'res' and put the domain into it
	$res = "" | select domain, result, message, txt, record, Type
	$res.domain = $domain
	
	If ($DNSResult.Type -eq "MX")
	{
		$MXRecord = "MX"
	}
	elseif ($DNSResult.Type -eq "TXT")
	{
		$MXRecord = "TXT"
	}
	elseif ($DNSResult -eq $null)
	{
		$MXRecord = "No Result"
	}
	else
	{
		$MXRecord = $DNSResult.Type
	}
	
	#Check to see if there is an SPF Result
	if ($y -ne $null)
	{
		#Print to the console that an SPF Exists
		Write-Host "SPF present: $($y.strings). Checking validity ..." -ForegroundColor Green
		
		#Launch the kitterman web check and setup the request
		$web = Invoke-WebRequest -Uri http://www.kitterman.com/spf/validate.html
		$web.forms[0].fields.domain = "$($y.name)"
		
		#Get the name of the domain to scan and send the data to kitterman, get and format the response
		$result = Invoke-RestMethod http://www.kitterman.com/getspf2.py -Body $web.forms[0].fields
		$message = $result.replace("`r`n", "--")
		
		#populate the array
		$res.message = $result
		$res.txt = $message
		$res.record = $($y.strings)
		$res.Type = $MXRecord
		
		#Scan for the result in the message
		if ($message -like "*passed*")
		{
			$res.result = "Passed"
		}
		else
		{
			$res.result = "FAIL"
		}
	}
	#If there was no SPF Record found run the following
	else
	{
		#populate the array with dummy values
		$res.message = "N/A"
		$res.result = "No SPF Record"
		$res.txt = "N/A"
		
		If ($y.Type -eq $null)
		{
			$type = "N/A"
			$res.Type = $MXRecord
		}
		
		If ($y.strings -eq $null)
		{
			$record = "N/A"
			$res.record = $record
		}
	}
	return $res
}


function Get-DNS ([String]$domain)
{
	resolve-dnsname $domain -type MX
	resolve-dnsname $domain -type TXT
}

#loop through the sites to scan
$SiteResults = @()
$SitestoScan | ForEach-Object{
	$SiteResults += Validate-SPF -domain $_.Sites
}

#collect the results and output to CSV
$SiteResults | Export-Csv -Path "$WorkingDir\results.csv"


