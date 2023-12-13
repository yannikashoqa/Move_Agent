#  Version 0.3

Clear-Host
Write-Host "################################  Start of Script  ################################"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
$ErrorActionPreference = 'Continue'

$DS_SYSTEMS_LIST = "$PSScriptRoot\DS_Computers.csv"
If (-Not (Test-Path -Path $DS_SYSTEMS_LIST)){
    Write-Host "[ERROR] DS_Computers.csv File Not found"
    Exit(0)
}

$ConfigFile = "$PSScriptRoot\TM-Config.json"
If (-Not (Test-Path -Path $ConfigFile)){
    Write-Host "[ERROR] Config File Not found"
    Exit(0)
}

$Config = (Get-Content $ConfigFile -Raw) | ConvertFrom-Json
$C1WS = $Config.C1WS
$C1API = $Config.C1API
$POLICY_SUFFIX = $Config.POLICY_SUFFIX
$DEFAULT_POLICYID = $Config.DEFAULT_POLICYID
$USE_PROXY = $Config.USE_PROXY
$PROXY_SERVER = $Config.PROXY_SERVER
$PROXY_PORT = $Config.PROXY_PORT
$LOG_FILE = $Config.LOG_FILE

$C1WS_headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$C1WS_headers.Add("Authorization", $C1API)
$C1WS_headers.Add("api-version", 'v1')
$C1WS_headers.Add("Content-Type", 'application/json')

$C1WS_HOST_URI = "https://" + $C1WS + "/api/"

$HostName = [System.Net.Dns]::GetHostName()
$HostNameFQDN = [System.Net.Dns]::GetHostByName($env:ComputerName).HostName

Clear-Variable -Name SystemName -ErrorAction SilentlyContinue
Clear-Variable -Name SystemPolicy -ErrorAction SilentlyContinue
Clear-Variable -Name WS_Computer_PolicyID -ErrorAction SilentlyContinue
$Date = Get-Date

# Check if Agent is already Installed
$Service = "Trend Micro Deep Security Agent1"
Try {
	$Service_Obj = get-service -ComputerName $HostName -Name $Service -ErrorAction SilentlyContinue
	If ($Service_Obj){
		write-host "[INFO] Service Exist: $Service"
		Add-Content $LOG_FILE "$Date    $HostName   INFO] Service Exist: $Service"
		Exit(0)
	}
}
Catch {
	Write-Host  "[ERROR] Failed to retreive local Services: $_"
    Add-Content $LOG_FILE "$Date    $HostName   [ERROR] Failed to retreive local Services: $_"
}

$Systems_List = Import-Csv $DS_SYSTEMS_LIST
foreach ($System in $Systems_List){
    If ($System.Name -eq $HostName){
        $SystemName = $System.Name
        $SystemPolicy = $System.Policy
    }elseif ($System.Name -eq $HostNameFQDN) {
        $SystemName = $System.Name
        $SystemPolicy = $System.Policy
    }elseif ($System.Name -like "*$HostName*"){  #Assuming Hostnames are unique within the DS computer list. This will cover any system that does not report hostname or FQDN to DS.
        $SystemName = $System.Name
        $SystemPolicy = $System.Policy
    }
}

If($null -eq $SystemName){
    Write-Host "[INFO] System Not Found: " $HostName $HostNameFQDN
    Add-Content $LOG_FILE "$Date    [INFO] System Not Found: $HostName $HostNameFQDN"
    Exit(0)
}

If ($null -eq $SystemPolicy -or $SystemPolicy -eq ""){
    Write-Host "[INFO] No Policy was found for $HostName. Using default Policy assignment with ID: $DEFAULT_POLICYID"
    Add-Content $LOG_FILE "$Date    $HostName   [INFO] No Policy was found for $HostName. Using default Policy assignment with ID: $DEFAULT_POLICYID"
    $WS_Computer_PolicyID = $DEFAULT_POLICYID
}else {
    $WS_Search_PolicyName = $SystemPolicy + $POLICY_SUFFIX
    $WS_Search_PolicyName
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
        If ($USE_PROXY){
            $Proxy_Server_Address = "http://" + $PROXY_SERVER + ":" + $PROXY_PORT
            $WS_Search_Policy = Invoke-RestMethod -Uri $C1WS_Search_Policies_URI -Method Post -Headers $C1WS_headers -Body $WS_Policy_QUERY_PARAMS -Proxy $Proxy_Server_Address
        }Else{
            $WS_Search_Policy = Invoke-RestMethod -Uri $C1WS_Search_Policies_URI -Method Post -Headers $C1WS_headers -Body $WS_Policy_QUERY_PARAMS
        }
        
        $WS_Computer_PolicyID = $WS_Search_Policy.policies.ID
        if ($WS_Search_Policy.policies.Count -eq 0){
            Write-Host "[INFO] Could not find policy: $WS_Search_PolicyName . Using Default Policy"
            Add-Content $LOG_FILE "$Date    $HostName   [INFO] Could not find policy: $WS_Search_PolicyName . Using Default Policy"
            $WS_Computer_PolicyID = $DEFAULT_POLICYID
        }
    }
    catch {
        Write-Host "[ERROR]	Failed to search for Policy.	$_"
        Add-Content $LOG_FILE "$Date    $HostName   [ERROR]	Failed to search for Policy.	$_"
        Exit(0)
    }
}

Write-Host "[INFO] Workload Security Policy ID $WS_Computer_PolicyID will be assigned to: $SystemName"
Add-Content $LOG_FILE "$Date    $HostName   [INFO] Workload Security Policy ID $WS_Computer_PolicyID will be assigned to: $SystemName"

###########################  End of Policy ID Lookup ###########################
# Paste below your C1WS Agent deployment script and replace the activation line policyid entry as follow: "policyid:$WS_Computer_PolicyID"
################################################################################

