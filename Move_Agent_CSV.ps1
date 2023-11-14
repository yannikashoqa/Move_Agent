#  Version 0.1
Function Check_Port {
	Param(	[Parameter(Mandatory=$true)][String]$HostName,
            [Parameter(Mandatory=$true)][String]$Port)

    $Socket = New-Object Net.Sockets.TcpClient
    $ErrorActionPreference = 'SilentlyContinue'	# Suppress error messages
    $Socket.Connect($HostName, $Port)	# Test Connection
    $ErrorActionPreference = 'Continue'	# Make error messages visible again
    if ($Socket.Connected){
        $Socket.Close()
        $Socket = $null
        Return 0
    }Else{
        $Socket = $null	
        Return 1			
    }
    $ErrorActionPreference = 'SilentlyContinue'	# Suppress error messages
}

Clear-Host
Write-Host "################################  Start of Script  ################################"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
$ErrorActionPreference = 'Stop'

$Config = (Get-Content "$PSScriptRoot\TM-Config.json" -Raw) | ConvertFrom-Json
$C1WS = $Config.C1WS
$C1API = $Config.C1API
$POLICY_SUFFIX = $Config.POLICY_SUFFIX
$DEFAULT_POLICYID = $Config.DEFAULT_POLICYID
$DS_SYSTEMS_LIST = "$PSScriptRoot\DS_Computers.csv"

$WS_Port_Status = Check_Port -HostName $C1WS -Port 443
If ($WS_Port_Status -eq 1){
    Write-Host "[ERROR]	Failed to connect to $C1WS on Port 443"
    Exit (0)
}Else{
    Write-Host "Connection to port 443 on $C1WS : OK"
}

$C1WS_headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$C1WS_headers.Add("Authorization", $C1API)
$C1WS_headers.Add("api-version", 'v1')
$C1WS_headers.Add("Content-Type", 'application/json')

$C1WS_HOST_URI = "https://" + $C1WS + "/api/"

$HostName = [System.Net.Dns]::GetHostName()
$HostNameFQDN = [System.Net.Dns]::GetHostByName($env:ComputerName).HostName

$Systems_List = Import-Csv $DS_SYSTEMS_LIST
foreach ($System in $Systems_List){
    If ($System.Name -eq $HostName){
        $SystemName = $System.Name
        $SystemPolicy = $System.Policy
    }elseif ($System.Name -eq $HostNameFQDN) {
        $SystemName = $System.Name
        $SystemPolicy = $System.Policy
    }
}

If($null -eq $SystemName){
    Write-Host " System Not Found: "$System.Name
    Exit(0)
}

If ($null -eq $SystemPolicy -or $SystemPolicy -eq ""){
    Write-Host "No Policy was found for $HostName. Using default Policy assignment with ID: $DEFAULT_POLICYID"
    $WS_Computer_PolicyID = $DEFAULT_POLICYID
}else {
    $WS_Search_PolicyName = $SystemPolicy + $POLICY_SUFFIX
    $C1WS_Search_Policies_URI = $C1WS_HOST_URI + "policies/search"
    $WS_Policy_QUERY_PARAMS = @{
        searchCriteria = @{
            fieldName   = "name"
            stringTest  = "equal"
            stringWildcards = "true"
            stringValue = $WS_Search_PolicyName
        }
    }

    $WS_Policy_QUERY_PARAMS = $WS_Policy_QUERY_PARAMS | ConvertTo-Json -Depth 4
    try {
        $WS_Search_Policy = Invoke-RestMethod -Uri $C1WS_Search_Policies_URI -Method Post -Headers $C1WS_headers -Body $WS_Policy_QUERY_PARAMS -SkipCertificateCheck 
        $WS_Computer_PolicyID = $WS_Search_Policy.policies.ID
        if ($WS_Search_Policy.policies.Count -eq 0){
            Write-Host "Could not find policy: $WS_Search_PolicyName . Using Default Policy"
            $WS_Computer_PolicyID = $DEFAULT_POLICYID
        }
    }
    catch {
        Write-Host "[ERROR]	Failed to search for Policy.	$_"
    }
}

$WS_Computer_PolicyID

###########################  End of Policy ID Lookup ###########################
# Paste below your C1WS Agent deployment script and replace the activation line policyid entry as follow: "policyid:$WS_Computer_PolicyID"
################################################################################

