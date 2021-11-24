<#
  .SYNOPSIS
  This script is used to garner device information from a single tenant and output that information to a CSV file
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
    $path = echo ([Environment]::GetFolderPath("Desktop")+"\MicrosoftDeviceReports")
    New-Item -ItemType Directory -Force -Path $path
    $customerDeviceReport = echo ([Environment]::GetFolderPath("Desktop")+"\MicrosoftDeviceReports\${customerDomain}.csv")

    #####Get Device information if it is available####
    try{
    $Devices = (Invoke-RestMethod -Uri 'https://graph.microsoft.com/beta/devices' -Headers $headers -Method Get -ContentType "application/json").value | Select-Object displayName, accountEnabled, operatingSystem, operatingSystemVersion, managementType,isCompliant, deviceOwnership,registrationDateTime, approximateLastSignInDateTime
    }catch{('Error calling devices MS Graph')} 

     #####Get MDM information if it is available####
    try{
      $MDMDevices = (Invoke-RestMethod -Uri 'https://graph.microsoft.com/beta/deviceManagement/managedDevices' -Headers $headers -Method Get -ContentType "application/json").value | Select-Object deviceName, joinType,userPrincipalName,isEncrypted,autopilotEnrolled, serialNumber
      }catch{('Error calling devices MS Graph, its possible this tenant does not have Intune')} 

    $DeviceObj = foreach ($device in $Devices) {
      [PSCustomObject]@{
        'DeviceName'                         = $device.displayName
        "Enabled"                            = $device.accountEnabled
        "OS"                                 = $device.operatingSystem
        'Version'                            = $device.operatingSystemVersion
        "JoinType"                           = ($MDMDevices | where-object { $_.deviceName -eq $device.displayName}).joinType
        "UserName"                           = ($MDMDevices | where-object { $_.deviceName -eq $device.displayName}).userPrincipalName
        "ManagementType"                     = $device.managementType
        "Compliance"                         = $device.isCompliant
        "DeviceOwnership"                    = $device.deviceOwnership
        "RegisteredDate"                     = $device.registrationDateTime
        "LastActivityDate"                   = $device.approximateLastSignInDateTime
        "AutopilotEnrolled"                  = ($MDMDevices | where-object { $_.deviceName -eq $device.displayName}).autopilotEnrolled
        "isEncrypted"                        = ($MDMDevices | where-object { $_.deviceName -eq $device.displayName}).isEncrypted
        "SerialNumber"                       = ($MDMDevices | where-object { $_.deviceName -eq $device.displayName}).serialNumber
    }
      
    }

    $DeviceObj | Export-CSV -Path $customerDeviceReport -NoTypeInformation -Append 