#  Version 0.1

Function Check_ICMP {
	Param(	[Parameter(Mandatory=$true)][String]$HostName)
	
	if (Test-Connection  -ComputerName $HostName -Count 2 -Quiet -ErrorAction SilentlyContinue) {
		Return 0	
	}Else{
		Return 1	
	}
}

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
$Manager = $Config.MANAGER
$APIKEY = $Config.APIKEY
$PORT = $Config.PORT
$C1WS = $Config.C1WS
$C1API = $Config.C1API
$POLICY_SUFFIX = $Config.POLICY_SUFFIX
$DEFAULT_POLICYID = $Config.DEFAULT_POLICYID

$DS_ICMP_Status = Check_ICMP -HostName $Manager
If ($DS_ICMP_Status -eq 1){
    Write-Host "[ERROR]	Failed to Ping $Manager"
    Exit (0)
}Else{
    Write-Host "ICMP Connection to $Manager : OK"	
}

$DS_Port_Status = Check_Port -HostName $Manager -Port $Port
If ($DS_Port_Status -eq 1){
    Write-Host "[ERROR]	Failed to connect to $Manager on Port $Port"
    Exit (0)
}Else{
    Write-Host "Connection to port $Port on $Manager : OK"
}

$WS_Port_Status = Check_Port -HostName $C1WS -Port 443
If ($WS_Port_Status -eq 1){
    Write-Host "[ERROR]	Failed to connect to $C1WS on Port 443"
    Exit (0)
}Else{
    Write-Host "Connection to port 443 on $C1WS : OK"
}

$DS_headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$DS_headers.Add("api-secret-key", $APIKEY)
$DS_headers.Add("api-version", 'v1')
$DS_headers.Add("Content-Type", 'application/json')

$C1WS_headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$C1WS_headers.Add("Authorization", $C1API)
$C1WS_headers.Add("api-version", 'v1')
$C1WS_headers.Add("Content-Type", 'application/json')

$DS_HOST_URI = "https://" + $Manager + ":" + $PORT + "/api/"
$C1WS_HOST_URI = "https://" + $C1WS + "/api/"

$ComputersAPIPath = "computers"
$DS_Search_Computers_URI = $DS_HOST_URI + $ComputersAPIPath + "/search"

$HostName = [System.Net.Dns]::GetHostName()
$HostNameFQDN = [System.Net.Dns]::GetHostByName($env:ComputerName).HostName

$Computer_QUERY_PARAMS = @{
    searchCriteria = @{
        fieldName   = "hostName"
        stringTest  = "equal"
        stringValue = $HostName
    }
}

$ComputerFQDN_QUERY_PARAMS = @{
    searchCriteria = @{
        fieldName   = "hostName"
        stringTest  = "equal"
        stringValue = $HostNameFQDN
    }
}
$Computer_QUERY_PARAMS = $Computer_QUERY_PARAMS | ConvertTo-Json -Depth 4
$ComputerFQDN_QUERY_PARAMS = $ComputerFQDN_QUERY_PARAMS | ConvertTo-Json -Depth 4

try {
    Write-Host "Searching Computer via Computer Name: $HostName "
    $DS_Search_Computer = Invoke-RestMethod -Uri $DS_Search_Computers_URI -Method Post -Headers $DS_headers -Body $Computer_QUERY_PARAMS -SkipCertificateCheck 
    $DS_Computer_PolicyID = $DS_Search_Computer.computers.PolicyID
}
catch {
    Write-Host "[ERROR]	Failed to search for Computer $HostName.	$_"
}

If ($DS_Search_Computer.computers.Count -eq 0){
    Write-Host "Searching Computer via FQDN: $HostNameFQDN"
    try {
        $DS_Search_Computer = Invoke-RestMethod -Uri $DS_Search_Computers_URI -Method Post -Headers $DS_headers -Body $ComputerFQDN_QUERY_PARAMS -SkipCertificateCheck 
        $DS_Computer_PolicyID = $DS_Search_Computer.computers.PolicyID
    }
    catch {
        Write-Host "[ERROR]	Failed to search for Computer $HostName.	$_"
    }
}

If ($DS_Search_Computer.computers.Count -eq 0){
    Write-Host "[INFO]: Failed to find the computer using both HostName and FQDN: ($HostName, $HostNameFQDN)"
    Exit(0)
}

$DS_Describe_Policy_URI = $DS_HOST_URI + "policies/" + $DS_Computer_PolicyID 
try {
    $DS_Describe_Policy = Invoke-RestMethod -Uri $DS_Describe_Policy_URI -Method Get -Headers $DS_headers -SkipCertificateCheck 
    $DS_PolicyName = $DS_Describe_Policy.name
}
catch {
    Write-Host "[ERROR]	Failed to retreive computer Policy Name.	$_"
}

If ($null -eq $DS_PolicyName){
    Write-Host "No Policy was found for $HostName. Using default Policy assignment with ID: $DEFAULT_POLICYID"
    $WS_Computer_PolicyID = $DEFAULT_POLICYID
}else {
    $WS_Search_PolicyName = $DS_PolicyName + $POLICY_SUFFIX
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
    }
    catch {
        Write-Host "[ERROR]	Failed to search for Policy.	$_"
    }
}

$WS_Computer_PolicyID

###########################  End of Policy ID Lookup ###########################
# Paste below your C1WS Agent deployment script and replace the activation line policyid entry as follow: "policyid:$WS_Computer_PolicyID"
################################################################################

