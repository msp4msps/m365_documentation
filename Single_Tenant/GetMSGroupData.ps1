<#
  .SYNOPSIS
  This script is used to garner group information from a single tenant and output that information to a CSV file
  .NOTES
  This script leverages the Secure Application model to authenticate to a customer tenant in which you have delegated privledges
  #>
  Param
  (

    [cmdletbinding()]
        [Parameter(Mandatory= $true)]
        [string]$ApplicationId,
        [Parameter(Mandatory= $true, HelpMessage="Enter your ApplicationSecret from the Secure Application Model")]
        [string]$ApplicationSecret,
        [Parameter(Mandatory= $true, HelpMessage="Enter your Partner Tenantid")]
        [string]$tenantID,
        [Parameter(Mandatory= $true, HelpMessage="Enter your refreshToken from the Secure Application Model")]
        [string]$refreshToken,
        [Parameter(Mandatory= $true)]
        [string]$customerTenantID
    )
    
# Check if the MSOnline PowerShell module has already been loaded.
if ( ! ( Get-Module MSOnline) ) {
  # Check if the MSOnline PowerShell module is installed.
  if ( Get-Module -ListAvailable -Name MSOnline ) {
      Write-Host -ForegroundColor Green "Loading the Azure AD PowerShell module..."
      Import-Module MsOnline
  } else {
      Install-Module MsOnline
  }
}

###MICROSOFT SECRETS#####

$ApplicationId = $ApplicationId
$ApplicationSecret = $ApplicationSecret
$tenantID = $tenantID
$refreshToken = $refreshToken
$secPas = $ApplicationSecret| ConvertTo-SecureString -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($ApplicationId, $secPas)





###Connect to your Own Partner Center to get a list of customers/tenantIDs #########
$aadGraphToken = New-PartnerAccessToken -ApplicationId $ApplicationId -Credential $credential -RefreshToken $refreshToken -Scopes 'https://graph.windows.net/.default' -ServicePrincipal -Tenant $tenantID
$graphToken = New-PartnerAccessToken -ApplicationId $ApplicationId -Credential $credential -RefreshToken $refreshToken -Scopes 'https://graph.microsoft.com/.default' -ServicePrincipal -Tenant $tenantID


Connect-MsolService -AdGraphAccessToken $aadGraphToken.AccessToken -MsGraphAccessToken $graphToken.AccessToken

 
$CustomerToken = New-PartnerAccessToken -ApplicationId $ApplicationId -Credential $credential -RefreshToken $refreshToken -Scopes 'https://graph.microsoft.com/.default' -Tenant $customerTenantID
$headers = @{ "Authorization" = "Bearer $($CustomerToken.AccessToken)" }
  
##GET DOMAIN 
$customerDomain = (Get-MsolDomain -TenantId $customerTenantID).name[1]

    #Define CSV Path 
    $path = echo ([Environment]::GetFolderPath("Desktop")+"\MicrosoftGroupsReports")
    New-Item -ItemType Directory -Force -Path $path
    $customerGroupReport = echo ([Environment]::GetFolderPath("Desktop")+"\MicrosoftGroupsReports\${customerDomain}.csv")

    #####Get Group information if it is available####
    try{
    $Groups = (Invoke-RestMethod -Uri 'https://graph.microsoft.com/v1.0/groups' -Headers $headers -Method Get -ContentType "application/json").value | Select-Object id, displayName, mail, groupTypes,createdDateTime,onPremisesSyncEnabled,securityEnabled,visibility,resourceBehaviorOptions,resourceProvisioningOptions
    }catch{('Error calling devices MS Graph')} 



    $GroupObj = foreach ($group in $Groups) {

      ##Get Owners
      try{
        $Owners = (Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/groups/$($group.id)/owners" -Headers $headers -Method Get -ContentType "application/json").value | Select-Object displayName
        }catch{('Error calling devices MS Graph')} 
        
      ##Get Members
      try{
        $Members = (Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/groups/$($group.id)/members" -Headers $headers -Method Get -ContentType "application/json").value | Select-Object displayName
        }catch{('Error calling devices MS Graph')}  

      ##Determine Group Type
      if($group.groupTypes -contains "Unified"){
        $GroupType = "Microsoft 365"
      } elseif( (!$group.groupTypes) -and $group.securityEnabled -eq $false){
        $GroupType = "Distribution"
      } else{
        $GroupType = "Security"
      }
      ##Determine Dynamic Or Assigned Membership
      if($group.groupTypes -contains "DynamicMembership"){
        $membership = "Dynamic"
      } else{
        $membership = "Assigned"
      }
      ##Determine Hide from GAL
      if($group.resourceBehaviorOptions -contains "HideGroupInOutlook"){
        $hidefromGal = $true
      } else{
        $hidefromGal = $false
      }

      ##Determine if Teams Channel Assoicated
      if($group.resourceProvisioningOptions -contains "Team"){
        $teamConnected = $true
      } else{
        $teamConnected = $false
      }


      [PSCustomObject]@{
        'GroupName'                          = $group.displayName
        "Email"                              = if($group.mail){$group.mail}else{"N/A"}
        "Group Type"                         = $GroupType
        'Membership Type'                    = $membership
        "Creation Date"                      = $group.createdDateTime
        "Source"                             = if($group.onPremisesSyncEnabled){"On-premise"}else{"Cloud"}
        "Security Enabled"                   = $group.securityEnabled
        "Visibility"                         = $group.visibility
        "HideFromGal"                        = $hidefromGal
        "Teams Connected"                    = $teamConnected
        "Owners"                             = $Owners.displayName -join ","
        "Members"                            = $Members.displayName -join ","
    }
      
    }

    

    $GroupObj | Export-CSV -Path $customerGroupReport -NoTypeInformation -Append 