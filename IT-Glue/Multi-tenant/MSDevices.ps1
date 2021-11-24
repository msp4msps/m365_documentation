<#
  .SYNOPSIS
  This script is used to garner devuce information from customer tenants and add that information as a flexible assets in IT Glue
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
        [string]$ITGlueAPIKey
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

########################## IT-Glue Information ############################
$ITGlueAPIKey = $ITGlueAPIKey
$APIEndpoint = "https://api.itglue.com"
$FlexAssetName = "Microsoft 365 Devices"
$Description = "Documentation for all devices enrolled into AzureAD/Intune"


write-host "Getting IT-Glue module" -ForegroundColor Green
 
If (Get-Module -ListAvailable -Name "ITGlueAPI") { 
    Import-module ITGlueAPI 
}
Else { 
    Install-Module ITGlueAPI -Force
    Import-Module ITGlueAPI
}
#Settings IT-Glue logon information
Add-ITGlueBaseURI -base_uri $APIEndpoint
Add-ITGlueAPIKey $APIKEy

write-host "Checking if Flexible Asset exists in IT-Glue." -foregroundColor green
$FilterID = (Get-ITGlueFlexibleAssetTypes -filter_name $FlexAssetName).data
if (!$FilterID) { 
    write-host "Does not exist, creating new." -foregroundColor green
    $NewFlexAssetData = 
    @{
        type          = 'flexible-asset-types'
        attributes    = @{
            name        = $FlexAssetName
            icon        = 'laptop'
            description = $description
        }
        relationships = @{
            "flexible-asset-fields" = @{
                data = @(
                    @{
                        type       = "flexible_asset_fields"
                        attributes = @{
                            order           = 1
                            name            = "Device Name"
                            kind            = "Text"
                            required        = $true
                            "show-in-list"  = $true
                            "use-for-title" = $true
                        }
                    },

                    @{
                        type       = "flexible_asset_fields"
                        attributes = @{
                            order          = 2
                            name           = "Enabled"
                            kind           = "Checkbox"
                            required       = $false 
                            "show-in-list" = $true
                        }
                    }
                    @{
                        type       = "flexible_asset_fields"
                        attributes = @{
                            order          = 3
                            name           = "OS"
                            kind           = "Text"
                            required       = $true
                            "show-in-list" = $true
                        }
                    }
                    @{
                        type       = "flexible_asset_fields"
                        attributes = @{
                            order          = 4
                            name           = "Version"
                            kind           = "Text"
                            required       = $false
                            "show-in-list" = $true
                        }
                    }
                    @{
                        type       = "flexible_asset_fields"
                        attributes = @{
                            order          = 5
                            name           = "Join Type"
                            kind           = "Text"
                            required       = $false
                            "show-in-list" = $true
                        }
                    }
                    @{
                        type       = "flexible_asset_fields"
                        attributes = @{
                            order          = 6
                            name           = "UserName"
                            kind           = "Text"
                            required       = $false
                            "show-in-list" = $true
                        }
                    }
                    @{
                        type       = "flexible_asset_fields"
                        attributes = @{
                            order          = 7
                            name           = "MDM"
                            kind           = "Checkbox"
                            required       = $false
                            "show-in-list" = $true
                        }
                    }
                    @{
                        type       = "flexible_asset_fields"
                        attributes = @{
                            order          = 8
                            name           = "Compliance State"
                            kind           = "Checkbox"
                            required       = $false
                            "show-in-list" = $true
                        }
                    }
                    @{
                        type       = "flexible_asset_fields"
                        attributes = @{
                            order          = 9
                            name           = "Device Ownership"
                            kind           = "Text"
                            required       = $false
                            "show-in-list" = $true
                        }
                    }
                    @{
                        type       = "flexible_asset_fields"
                        attributes = @{
                            order          = 10
                            name           = "Registered Date"
                            kind           = "Date"
                            required       = $false
                            "show-in-list" = $true
                        }
                    }
                    @{
                        type       = "flexible_asset_fields"
                        attributes = @{
                            order          = 11
                            name           = "Last Activity Date"
                            kind           = "Date"
                            required       = $false
                            "show-in-list" = $true
                        }
                    }
                    @{
                        type       = "flexible_asset_fields"
                        attributes = @{
                            order          = 12
                            name           = "Autopilot Enrolled"
                            kind           = "Checkbox"
                            required       = $false
                            "show-in-list" = $true
                        }
                    }
                    @{
                        type       = "flexible_asset_fields"
                        attributes = @{
                            order          = 13
                            name           = "Encrypted"
                            kind           = "Checkbox"
                            required       = $false
                            "show-in-list" = $true
                        }
                    }
                    @{
                        type       = "flexible_asset_fields"
                        attributes = @{
                            order          = 14
                            name           = "Serial Number"
                            kind           = "Text"
                            required       = $false
                            "show-in-list" = $true
                        }
                    }
                    @{
                        type       = "flexible_asset_fields"
                        attributes = @{
                            order          = 15
                            name           = "Configurations"
                            'tag-type'     = "Configurations"
                            kind           = "Tag"
                            required       = $false
                            "show-in-list" = $true
                        }
                    }
                    @{
                      type       = "flexible_asset_fields"
                      attributes = @{
                          order          = 16
                          name           = "Investigate"
                          kind           = "Text"
                          required       = $false
                          "show-in-list" = $true
                      }
                  }
                     
                )
            }
        }
    }
    New-ITGlueFlexibleAssetTypes -Data $NewFlexAssetData
    $FilterID = (Get-ITGlueFlexibleAssetTypes -filter_name $FlexAssetName).data
}


#Grab all IT-Glue contacts to match the domain name.
write-host "Getting IT-Glue contact list" -foregroundColor green
$i = 1
$AllITGlueContacts = do {
    $Contacts = (Get-ITGlueContacts -page_size 1000 -page_number $i).data.attributes
    $i++
    $Contacts
    Write-Host "Retrieved $($Contacts.count) Contacts" -ForegroundColor Yellow
}while ($Contacts.count % 1000 -eq 0 -and $Contacts.count -ne 0) 


$i=1
$AllITGlueConfigurations = do {
    $Configs = (Get-ITGlueConfigurations -page_size 1000 -page_number $i).data
    $i++
    $Configs
    Write-Host "Retrieved $($Configs.count) Configurations" -ForegroundColor Yellow
}while ($Configs.count % 1000 -eq 0 -and $Configs.count -ne 0) 

$DomainList = foreach ($Contact in $AllITGlueContacts) {
    $ITGDomain = ($contact.'contact-emails'.value -split "@")[1]
    [PSCustomObject]@{
        Domain   = $ITGDomain
        OrgID    = $Contact.'organization-id'
        Combined = "$($ITGDomain)$($Contact.'organization-id')"
    }
} 


###Connect to your Own Partner Center to get a list of customers/tenantIDs #########
$aadGraphToken = New-PartnerAccessToken -ApplicationId $ApplicationId -Credential $credential -RefreshToken $refreshToken -Scopes 'https://graph.windows.net/.default' -ServicePrincipal -Tenant $tenantID
$graphToken = New-PartnerAccessToken -ApplicationId $ApplicationId -Credential $credential -RefreshToken $refreshToken -Scopes 'https://graph.microsoft.com/.default' -ServicePrincipal -Tenant $tenantID


Connect-MsolService -AdGraphAccessToken $aadGraphToken.AccessToken -MsGraphAccessToken $graphToken.AccessToken

$customers = Get-MsolPartnerContract -All
 
Write-Host "Found $($customers.Count) customers in Partner Center." -ForegroundColor DarkGreen

foreach ($customer in $customers) {
  Write-Host "Found $($customer.Name) in Partner Center" -ForegroundColor Green

  $CustomerDomains = Get-MsolDomain -TenantId $customer.TenantID
  $orgid = foreach ($customerDomain in $customerdomains) {
      ($domainList | Where-Object { $_.domain -eq $customerDomain.name }).'OrgID'
  }

  $orgID = $orgid | Select-Object -Unique
  if(!$orgID){
     Write-Host "Customer does not exist in IT-Glue" -ForegroundColor Red
  }
  if($orgID){

    ###Get Access Token########
    $CustomerToken = New-PartnerAccessToken -ApplicationId $ApplicationId -Credential $credential -RefreshToken $refreshToken -Scopes 'https://graph.microsoft.com/.default' -Tenant $customer.TenantID
    $headers = @{ "Authorization" = "Bearer $($CustomerToken.AccessToken)" }
    

          #####Get Device information if it is available####
          try{
            $Devices = (Invoke-RestMethod -Uri 'https://graph.microsoft.com/beta/devices?top=3' -Headers $headers -Method Get -ContentType "application/json").value | Select-Object displayName, accountEnabled, operatingSystem, operatingSystemVersion, managementType,isCompliant, deviceOwnership,registrationDateTime, approximateLastSignInDateTime,enrollmentType
            }catch{('Error calling devices MS Graph')} 
        
             #####Get MDM information if it is available####
            try{
              $MDMDevices = (Invoke-RestMethod -Uri 'https://graph.microsoft.com/beta/deviceManagement/managedDevices' -Headers $headers -Method Get -ContentType "application/json").value | Select-Object deviceName, joinType,userPrincipalName,isEncrypted,autopilotEnrolled, serialNumber
              }catch{('Error calling devices MS Graph, its possible this tenant does not have Intune')} 
            if($Devices){
            
              $DeviceObj = foreach ($device in $Devices) {
              [PSCustomObject]@{
                'DeviceName'                         = $device.displayName
                "Enabled"                            = $device.accountEnabled
                "OS"                                 = $device.operatingSystem
                'Version'                            = $device.operatingSystemVersion
                "JoinType"                           = if(($MDMDevices | where-object { $_.deviceName -eq $device.displayName}).joinType){($MDMDevices | where-object { $_.deviceName -eq $device.displayName}).joinType}else{$device. enrollmentType}
                "UserName"                           = ($MDMDevices | where-object { $_.deviceName -eq $device.displayName}).userPrincipalName
                "MDM"                                = if($device.managementType){$device.managementType}else{$false}
                "Compliance"                         = if($device.isCompliant){$device.isCompliant}else{"N/A"}
                "DeviceOwnership"                    = $device.deviceOwnership
                "RegisteredDate"                     = $device.registrationDateTime
                "LastActivityDate"                   = $device.approximateLastSignInDateTime
                "AutopilotEnrolled"                  = ($MDMDevices | where-object { $_.deviceName -eq $device.displayName}).autopilotEnrolled
                "isEncrypted"                        = ($MDMDevices | where-object { $_.deviceName -eq $device.displayName}).isEncrypted
                "SerialNumber"                       = ($MDMDevices | where-object { $_.deviceName -eq $device.displayName}).serialNumber
            }
              
            }

    forEach($device in $DeviceObj){
  
        $FlexAssetBody =
        @{
        type       = 'flexible-assets'
        attributes = @{
            traits = @{
             'device-name'              = $device.DeviceName
             'enabled'                  = $device.Enabled
             'os'                       = $device.OS
             'version'                  = $device.Version
             'join-type'                = $device.JoinType
             'username'                 = $device.UserName
             'mdm'                      = $device.MDM
             'device-ownership'         = $device.DeviceOwnership
             'compliance-state'         = $device.Compliance
             'registered-date'          = $device.RegisteredDate
             'last-activity-date'       = $device.LastActivityDate
             'autopilot-enrolled'       = $device.autopilotEnrolled | Out-String
             'encrypted'                = $device.isEncrypted | Out-String
             'serial-number'            = $device.serialNumber
             'configurations'           = ($AllITGlueConfigurations | where-object { $_.attributes.name -eq $device.DeviceName}).id
             'investigate'              = "https://aad.portal.azure.com/$($customer.TenantID)/#blade/Microsoft_AAD_Devices/DevicesMenuBlade/Devices/menuId/"
            }
        }
    }
    $ExistingFlexAsset = (Get-ITGlueFlexibleAssets -filter_flexible_asset_type_id $($filterID.id) -filter_organization_id $orgID).data | Where-Object { $_.attributes.traits.'device-name' -eq $device.DeviceName}
        #If the Asset does not exist, we edit the body to be in the form of a new asset, if not, we just update.
        if (!$ExistingFlexAsset) {
            $FlexAssetBody.attributes.add('organization-id', $orgID)
            $FlexAssetBody.attributes.add('flexible-asset-type-id', $($filterID.ID))
            write-host "Creating Device $($device.deviceName) for $($customer.name) into IT-Glue" -ForegroundColor Green
            New-ITGlueFlexibleAssets -data $FlexAssetBody
        }
        else {
            write-host "Updating Device $($device.deviceName) for $($customer.name) into IT-Glue"  -ForegroundColor Yellow
            $ExistingFlexAsset = $ExistingFlexAsset | select-object -last 1
            Set-ITGlueFlexibleAssets -id $ExistingFlexAsset.id -data $FlexAssetBody
        }
    }
    }}}