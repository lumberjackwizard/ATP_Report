#Created using PowerShell 7.4.5

############################
# Functions
############################

function Invoke-CheckNSXCredentials(){
	$checkUri = 'https://'+$nsxmgr+'/policy/api/v1/infra'

	#using Invoke-WebRequst to evaluate the statuscode that is returned from the NSX Manager
	$response = Invoke-WebRequest -Uri $checkUri -Method Get -SkipCertificateCheck -Authentication Basic -Credential $Cred -SkipHttpErrorCheck
	
	if ($response.StatusCode -eq 200) {
		Write-Host "Successfully connected to NSX Manager. Status: 200 OK"
	} else {
		Write-Host "Failed to connect to NSX Manager." 
		Write-Host "Status: $($response.StatusCode)"
		Write-Host "Error Message:" ($response.Content)
		Write-Host "Exiting script... Please try again. "
		exit
	}

}

function Get-NSXDFW {

	# The below gathers all securitypolicies, groups, and services from infra, storing it in 
	# the $rawpolicy variable 

	Write-Host "Requesting data from target NSX Manager..."

	$rawpolicy = Invoke-RestMethod -Uri $Uri -SkipCertificateCheck -Authentication Basic -Credential $Cred
	$rawservices = Invoke-RestMethod -Uri $SvcUri -SkipCertificateCheck -Authentication Basic -Credential $Cred


	# Gathering IDS policies

	Write-Host "Gathering IDS/IPS & Malware Prevention Policies and rules..."

	$idspolicies = $rawpolicy.children.Domain.children.IdsSecurityPolicy | Where-object {$_.id -And $_.id -ne 'Default'} | Sort-Object -Property internal_sequence_number



	# Gathering Groups

	Write-Host "Gathering Groups..."

	$allgroups = $rawpolicy.children.Domain.children.Group | Where-object {$_.id}


	Write-Host "Gathering Serivces..."

	$allservices = $rawservices.children.Service | Where-object {$_.id}


	# Gathering Context Profiles

	Write-Host "Gathering IDS/IPS & Malware Prevention Profiles..."

	$allIdsProfiles = $rawpolicy.children.IdsProfile | Where-object {$_.id}
	$allMalwareProfiles = $rawpolicy.children.MalwarePreventionProfile | Where-Object {$_.id}


	return [PSCustomObject]@{
		AllIDSPolicies = $idspolicies
		AllGroups = $allgroups
		AllServices = $allservices
		AllIDSProfiles = $allIdsProfiles
		AllMalwareProfiles = $allMalwareProfiles
	}

}





function Invoke-GenerateBreakdownReport {
	

	$policy_count = 0
	$rule_count = 0
	foreach ($idsPolicy in $allIdsPolicies | Where-object {$_._create_user -ne 'system' -And $_._system_owned -eq $False}) {
		$policy_count++
		foreach ($rule in $idsPolicy.children.IdsRule){
			$rule_count++
		}
	}


	$ids_pro_count = 0
	foreach ($ids_pro in $allIdsProfiles | Where-object {$_._create_user -ne 'system' -And $_._system_owned -eq $False}){
		$ids_pro_count++
	}

	$report_counts = @($policy_count,$rule_count,$ids_pro_count)


	return $report_counts
}


function Invoke-GeneratePolicyReport {

	# Loop through the data to create rows with conditional formatting
	foreach ($idsPolicy in $allIdsPolicies | Where-object {$_._create_user -ne 'system' -And $_._system_owned -eq $False}) {
    # Ensure that lines that contain the category and policy are a unique color compared to the rows that have rules
	
    	$rowStyle = ''
    	if ($idsPolicy.category -eq "ThreatRules") {
			$rowStyle = ' style="background-color: #4682B4; "' 
		} 
    
    # Add the row to the HTML
		$html_policy += "    <tr$rowStyle>
			<td style='font-weight: bold;'>$($idsPolicy.display_name)</td>
			<td colspan=7></td>
		</tr>`n"

		
	
	# Gathering all rules and polices

		
		$sortrules = $idsPolicy.children.IdsRule | Sort-Object -Property sequence_number
	
		$rowCount = 0
		foreach ($rule in $sortrules | Where-object {$_.id}){
		
			
			$ruleentryname = $rule.display_name
			$ruleentryaction = $rule.action
	
			$ruleentrysrc = ""
			$ruleentrydst = ""
			$ruleentrysvc = ""
			$ruleentryidspro = ""
			$ruleentryappliedto = ""

			foreach ($srcgroup in $rule.source_groups){
				$n = 0
				foreach ($filteredgroup in $allGroups){
					if ($filteredgroup.path -eq $srcgroup){
						$ruleentrysrc += $filteredgroup.display_name + "`n"
						$n = 1
						break
					}
					
				}
				if ($n -eq "0") {
					$ruleentrysrc += $srcgroup + "`n"
					}	
			}
			
			
			foreach ($dstgroup in $rule.destination_groups){  
				$n = 0
				foreach ($filteredgroup in $allGroups){
					if ($filteredgroup.path -eq $dstgroup){
						$ruleentrydst += $filteredgroup.display_name + "`n"
						$n = 1
						break
					}
					
				}
				if ($n -eq "0") {
					$ruleentrydst += $dstgroup + "`n"
				}
			}	

			foreach ($svcgroup in $rule.services){ 
				$n = 0
				foreach ($filsvc in $allServices){
					if ($filsvc.path -eq $svcgroup){
						$ruleentrysvc += $filsvc.display_name + "`n"
						$n = 1
						break
					}
					
				}
				if ($n -eq "0") {
					$ruleentrysvc += $svcgroup + "`n"
				}							
			}
			
			foreach ($IdsProfile in $rule.ids_profiles){  
				$n = 0
				foreach ($filIdsPro in $allIdsProfiles){
					if ($filIdsPro.path -eq $IdsProfile){
						$ruleentryidspro += $filIdsPro.display_name + "`n"
						$n = 1
						break
					}					
				}

				foreach ($filMalwarePro in $allMalwareProfiles){
					if ($filMalwarePro.path -eq $IdsProfile){
						$ruleentryidspro += $filMalwarePro.display_name + "`n"
						$n = 1
						break
					}					
				}


				if ($n -eq "0") {
					$ruleentryidspro += $IdsProfile + "`n"
				}
			}

			foreach ($appliedto in $rule.scope){ 
				$n = 0
				foreach ($filteredgroup in $allGroups){
					if ($filteredgroup.path -eq $appliedto){
						$ruleentryappliedto += $filteredgroup.display_name + "`n"
						$n = 1
						break
					}
					
				}
				if ($n -eq "0") {
					$ruleentryappliedto += $appliedto + "`n"
				}							
			}
				
			$rowCount++
			
			# Add the row to the HTML
			if ($rowCount % 2) {
				$rowStyle2 = ' style="background-color: #B0C4DE;"'
			} else { 
				$rowStyle2 = ' style="background-color: #949BAF;"'
			}

			# Adding logic to alter the colors of the first two columns depending on the policy category

	
			if ($idsPolicy.category -eq "ThreatRules") {
				$nullStyle = ' style="background-color: #6FA3D1; border-bottom: none; border-top: none;"></td' 
			}
	

			$html_policy += "    <tr$rowStyle2>
			<td$nullStyle>
			<td style='vertical-align: middle;'>$($ruleentryname)</td>
			<td style='vertical-align: middle;'>$($ruleentrysrc)</td>
			<td style='vertical-align: middle;'>$($ruleentrydst)</td>
			<td style='vertical-align: middle;'>$($ruleentrysvc)</td>
			<td style='vertical-align: middle;'>$($ruleentryidspro)</td>
			<td style='vertical-align: middle;'>$($ruleentryappliedto)</td>
			<td style='vertical-align: middle;'>$($ruleentryaction)</td>
			</tr>`n"
			
			
		}  
	}

	


   
	return $html_policy
}


function Invoke-GenerateIDSProfileReport {

	# Loop through the data to create rows with conditional formatting
	foreach ($idsprofile in $allIdsProfiles | Where-object {$_._create_user -ne 'system' -And $_._system_owned -eq $False}) {
    # Ensure that lines that contain the category and policy are a unique color compared to the rows that have rules
    	
		$rowStyle = ' style="background-color: #B0C4DE; "' 
	
		 
    
    # Add the row to the HTML
		$html_ids_profile += "    <tr$rowStyle>
			<td style='font-weight: bold;'>$($idsprofile.display_name)</td>
			<td>$($idsprofile.profile_severity)</td>
			
		</tr>`n"

	}
  
	return $html_ids_profile
}

function Invoke-GenerateFullReport {

	Write-Host "Generating output file..."

	# Start the HTML 
	$html = @"

	<html>
	<head>
	$header
	</head>
	<body>
	<div>
        <img src="logo.png" alt="Logo" class="logo">
    </div>
	<p style="text-align:center;">
        <span style="font-size:22px;"><strong><u>ATP Report</u></strong></span>
    </p>
    <p>&nbsp;</p>
    <table style="width: 60%; margin: 0 auto; border-collapse: collapse; font-size: 16px;">
        <tr>
            <td style="padding: 10px; border-bottom: 1px solid #ccc;">Number of Distributed IDS/IPS & Malware Prevention Policies:</td>
            <td style="padding: 10px; border-bottom: 1px solid #ccc; text-align: right;"><b>$($report_counts[0])</b></td>
        </tr>
        <tr>
            <td style="padding: 10px; border-bottom: 1px solid #ccc;">Number of Distributed IDS/IPS & Malware Prevention Rules:</td>
            <td style="padding: 10px; border-bottom: 1px solid #ccc; text-align: right;"><b>$($report_counts[1])</b></td>
        </tr>
        <tr>
            <td style="padding: 10px; border-bottom: 1px solid #ccc;">Number of User Created IDS/IPS Profiles:</td>
            <td style="padding: 10px; border-bottom: 1px solid #ccc; text-align: right;"><b>$($report_counts[2])</b></td>
        </tr>
    </table>
	<p>&nbsp;</p>
	<p style="text-align:center;"><span style="font-size:18px;"><strong><u>IDS/IPS & Malware Prevention Policies</u></strong></span></p>
	<table>
		<thead>
			<tr>
				<th>IDS/IPS Policy Name</th>
				<th>Rule Name</th>
				<th>Source Groups</th>
				<th>Destination Groups</th>
				<th>Services</th>
				<th>Security Profiles</th>
				<th>Applied To</th>
				<th>Action</th>
			</tr>
		</thead>
		<tbody>
"@


		$html += $html_policy


		#close the security policies table and start the IDS Profiles table
		$html += @"
		</tbody>
	</table>
		<p>&nbsp;</p>
	<p style="text-align:center;"><span style="font-size:18px;"><strong><u>IDS/IPS Profiles</u></strong></span></p>
	<table>
		<thead>
			<tr>
				<th>Name</th>
				<th>Included Intrusion Severities</th>
			</tr>
		</thead>
		<tbody>
"@		
		
		$html += $html_ids_profile
		#close the IDS Profiles table and the entire html
		$html += @"

		</tbody>
		<tfoot>
			<tr style="border-top: 2px solid black;"></tr>
		</tfoot>
		</table>
		<p>&nbsp;</p>
		<p>&nbsp;</p>
		<p>&nbsp;</p>
		</body>
		</html>
"@
	
	$html | Set-Content -Path 'output.html'  # Save to an HTML file

}


#############################
# HTML Configuration elements
#############################


#This is formatting data for the later creation of the html file 

$header = @"
<style>
table {
font-size: 14px;
border-collapse: collapse;
width: 100%; 
font-family: Arial, Helvetica, sans-serif;
} 

    td {
padding: 4px;
margin: 0;
border: 1px solid #4d4d4d;
word-wrap: break-word;
overflow-wrap: break-word;
white-space: pre-wrap;
max-width: 300px;
}

    th {
        background: #395870;
        background: linear-gradient(#49708f, #293f50);
        color: #fff;
        font-size: 11px;
        text-transform: uppercase;
        padding: 10px 15px;
        vertical-align: middle;
		border: 1px solid #4d4d4d;
}


	td:nth-child(1), th:nth-child(1),
	td:nth-child(2), th:nth-child(2) {
    font-weight: bold;                   /* Makes text bold for the first two columns */
	}

        #CreationDate {

        font-family: Arial, Helvetica, sans-serif;
        color: #ff3300;
        font-size: 12px;

    }

.logo {
            position: absolute;
            top: 10px;
            right: 10px;
            width: 200px; /* Adjust size as needed */
            height: auto;
        }
    
</style>
"@

$html_policy = " "



############################################
# Main
############################################


# Temporarily hard setting nsxmgr and credentials for development. Get-Credential will be used in the future. 

$nsxmgr = '172.16.10.11'
$nsxuser = 'admin'
$nsxpasswd = ConvertTo-SecureString -String 'VMware1!VMware1!' -AsPlainText -Force
$Cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $nsxuser, $nsxpasswd

#$nsxmgr = Read-Host "Enter NSX Manager IP or FQDN"
#$Cred = Get-Credential -Title 'NSX Manager Credentials' -Message 'Enter NSX Username and Password'

# Uri will get only securitypolices, groups, and context profiles under infra
# SvcUri will gather all services under infra


$Uri = 'https://'+$nsxmgr+'/policy/api/v1/infra?type_filter=IdsSecurityPolicy;Group;IdsProfile;MalwarePreventionProfile;'
$SvcUri = 'https://'+$nsxmgr+'/policy/api/v1/infra?type_filter=Service;'


Invoke-CheckNSXCredentials

$allpolicies = Get-NSXDFW

$allIdsPolicies = $allpolicies.AllIDSPolicies
$allGroups = $allpolicies.AllGroups
$allServices = $allpolicies.AllServices
$allIdsProfiles = $allpolicies.AllIDSProfiles
$allMalwareProfiles = $allpolicies.AllMalwareProfiles



$html_policy = Invoke-GeneratePolicyReport

$html_ids_profile = Invoke-GenerateIDSProfileReport

$report_counts = Invoke-GenerateBreakdownReport


Invoke-GenerateFullReport







