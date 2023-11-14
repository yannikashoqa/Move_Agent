# Move DS Agentless Systems to C1WS


AUTHOR		: Yanni Kashoqa

TITLE		: Move DS Agentless Agents to Cloud One Workload Security

DESCRIPTION	: This Powershell script will identify the local systems's policy and use it for the activatation of a newly installed agent from Cloud One Workload Security.


FEATURES
- Move Deep Security Agentless protected systems to Cloud One Workload Secuerity while maintaining the same policy that was previously migrated.

REQUIRMENTS
- PowerShell 5.x
- Paste your Cloud One Workload Security deployment script at the bottom of the Move_Agent.ps1.
- Change the activation line to replace the policyid entry as follow: "policyid:$WS_Computer_PolicyID"
- If using the Move_Agent_CSV.ps1, export the computer list from Deep Security as DS_Computers.csv and place the file in same folder as the script. File should have a minimum of name and policy headers/fields.
- Create a TM-Config.json in the same folder with the following content:
- For Move_Agent_API.ps1:
~~~~JSON
{
    "MANAGER": "dsm.local.com",
    "PORT"   : "4119",
    "APIKEY" : "DS_APIKey",
    "C1WS"   : "workload.us-1.cloudone.trendmicro.com",
    "C1API"  : "ApiKey C1APIKey",
    "DEFAULT_POLICYID" : 1,
    "POLICY_SUFFIX" : ""
}
~~~~

- For Move_Agent_CSV.ps1:
~~~~JSON
{
    "C1WS"   : "workload.us-1.cloudone.trendmicro.com",
    "C1API"  : "ApiKey C1APIKey",
    "DEFAULT_POLICYID" : 1,
    "POLICY_SUFFIX" : ""
}
~~~~

- An API Key created on the Deep Security Manager 
- An API Key created on the Cloud One console
- The API Key Role minimum requirement is Read Only access to Workload Security/Deep Security
- The API Key format in the TM-Config.json for Cloud One is "ApiKey YourAPIKey"
- "MANAGER": Local DSM FQDN
- "PORT"   : Local DSM management port, default is 4119,
- "APIKEY" : Local DSM API Key. The API Key Role minimum requirement is Read Only access
- "C1WS"   : Cloud One Workload Security FQDN.  For US-1 region: workload.us-1.cloudone.trendmicro.com
- "C1API"  : Cloud One API Key with the format: ApiKey C1APIKey
- "DEFAULT_POLICYID" : Policy ID to be applied incase the Agentless system did not have a policy assigned to it.
- "POLICY_SUFFIX" : This is the date/time suffix that was added to the policies during the Policy Migration tool in Deep Security. Make sure to include the space before the text.  Here is an example:  " (2023-10-26T19:14:38Z DS_FQDN)"
