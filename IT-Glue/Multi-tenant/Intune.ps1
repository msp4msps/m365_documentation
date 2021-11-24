<#
  .SYNOPSIS
  This script is used to garner Intune information customer tenants and add that information as a flexible assets in IT Glue
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
$APIKey = "ITG.9eddd159f5f9510e32c4ca3052149c0d.LeSzbZsyHG9QpgfJnLhe_35InsJFSPtTOaM3Gn5yjTE95fPXBLQdASzCLiIK2tSR"
$APIEndpoint = "https://api.itglue.com"
$FlexAssetName = "Intune Settings"
$Description = "Documentation for all Intune Related Settings"

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
            icon        = 'device'
            description = $description
        }
        relationships = @{
            "flexible-asset-fields" = @{
                data = @(
                    @{
                        type       = "flexible_asset_fields"
                        attributes = @{
                            order           = 1
                            name            = "Customer Name"
                            kind            = "Text"
                            required        = $true
                            "show-in-list"  = $true
                            "use-for-title" = $true
                        }
                    },
                    @{
                        type       = "flexible_asset_fields"
                        attributes = @{
                            order           = 2
                            name            = "Windows Compliance Policies"
                            kind            = "Textbox"
                            required        = $false
                            "show-in-list"  = $true
                        }
                    },

                    @{
                        type       = "flexible_asset_fields"
                        attributes = @{
                            order          = 3
                            name           = "macOS Compliance Policies"
                            kind           = "Textbox"
                            required       = $false 
                            "show-in-list" = $true
                        }
                    }
                    @{
                        type       = "flexible_asset_fields"
                        attributes = @{
                            order          = 4
                            name           = "iOS Compliance Policies"
                            kind           = "Textbox"
                            required       = $false
                            "show-in-list" = $true
                        }
                    }
                    @{
                        type       = "flexible_asset_fields"
                        attributes = @{
                            order          = 5
                            name           = "Android Compliance Policies"
                            kind           = "Textbox"
                            required       = $false
                            "show-in-list" = $true
                        }
                    }
                    @{
                        type       = "flexible_asset_fields"
                        attributes = @{
                            order          = 6
                            name           = "Configuration Profiles"
                            kind           = "Textbox"
                            required       = $false
                            "show-in-list" = $true
                        }
                    }
                    @{
                        type       = "flexible_asset_fields"
                        attributes = @{
                            order          = 7
                            name           = "Group Policy"
                            kind           = "Textbox"
                            required       = $false
                            "show-in-list" = $true
                        }
                    }
                    @{
                        type       = "flexible_asset_fields"
                        attributes = @{
                            order          = 8
                            name           = "Applications"
                            kind           = "Textbox"
                            required       = $false
                            "show-in-list" = $true
                        }
                    }
                    @{
                        type       = "flexible_asset_fields"
                        attributes = @{
                            order          = 9
                            name           = "WIP without Enrollment"
                            kind           = "Textbox"
                            required       = $false
                            "show-in-list" = $true
                        }
                    }
                    @{
                        type       = "flexible_asset_fields"
                        attributes = @{
                            order          = 10
                            name           = "WIP with Enrollment"
                            kind           = "Textbox"
                            required       = $false
                            "show-in-list" = $true
                        }
                    }
                    @{
                        type       = "flexible_asset_fields"
                        attributes = @{
                            order          = 11
                            name           = "iOS App Protection Policies"
                            kind           = "Textbox"
                            required       = $false
                            "show-in-list" = $true
                        }
                    }
                    @{
                        type       = "flexible_asset_fields"
                        attributes = @{
                            order          = 12
                            name           = "Android App Protection Policies"
                            kind           = "Textbox"
                            required       = $false
                            "show-in-list" = $true
                        }
                    }
                    @{
                        type       = "flexible_asset_fields"
                        attributes = @{
                            order          = 13
                            name           = "Managed App Configuration Policies"
                            kind           = "Textbox"
                            required       = $false
                            "show-in-list" = $true
                        }
                    }
                    @{
                        type       = "flexible_asset_fields"
                        attributes = @{
                            order          = 14
                            name           = "Managed Device App Configuration Policies"
                            kind           = "Textbox"
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
 
Write-Host "Getting org info for $($customer.name)" -ForegroundColor Blue

$WinInfoProtectWEObj = ""
$WinInfoProtectEObj = ""
$iOSAppProtectionObj = ""
$AndroidAppProtectionObj = ""
$macOSComplianceObj = ""
$iOSComplianceObj = ""
$AndroidComplianceObj = ""
$Win10ComplianceObj = ""
$GroupPolicyObj = ""
$ConfigProfileObj = ""
$AppObj = ""
$MobileAppConfigObj = ""
$TargetedAppObj = 

$CustomerDomains = Get-MsolDomain -TenantId $customer.TenantID
$orgid = foreach ($customerDomain in $customerdomains) {
    ($domainList | Where-Object { $_.domain -eq $customerDomain.name }).'OrgID'
}

$orgID = $orgid | Select-Object -Unique
if(!$orgID){
   Write-Host "Customer does not exist in IT-Glue" -ForegroundColor Red
}

if($orgid){

 ##Get Access Token########
$CustomerToken = New-PartnerAccessToken -ApplicationId $ApplicationId -Credential $credential -RefreshToken $refreshToken -Scopes 'https://graph.microsoft.com/.default' -Tenant $customer.TenantID
$headers = @{ "Authorization" = "Bearer $($CustomerToken.AccessToken)" }


#####App Protection Policies#####

##Windows Information Protection-WithoutEnrollment#### 
try{
  Write-Host "Getting WIP Policies" -ForegroundColor Green
  $AllWindowsInfoProtectionWE = ""
  $AllWindowsInfoProtectionWE = (Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceAppManagement/windowsInformationProtectionPolicies" -Headers $Headers -Method Get -ContentType "application/json").value | Select-Object * -ExcludeProperty roleScopeTagIds,version,mdmEnrollmentUrl
  
  $WinInfoProtectWEObj = foreach ($policy in $AllWindowsInfoProtectionWE) {
    $policyInfo = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceAppManagement/windowsInformationProtectionPolicies/$($policy.id)" -Headers $Headers -Method Get -ContentType "application/json" | Select-Object id, displayName, protectedApps, exemptApps
  
    [PSCustomObject]@{
      id   = $policyInfo.id
      displayName = $policyInfo.displayName
      managementType = "Without Enrollment"
      createdDateTime  =$policy.createdDateTime
      lastModifiedDateTime = $policy.lastModifiedDateTime
      enforcementLevel = $policy.enforcementLevel
      enterpriseDomain  =$policy.enterpriseDomain
      protectedApps = $policyInfo.protectedApps.displayName -join(" ")
      exemptApps = $policyInfo.exemptApps.displayName -join(" ")
      isAssigned = $policy.isAssigned
      protectionUnderLockConfigRequired = $policy.protectionUnderLockConfigRequired
      dataRecoveryCertificate = $policy.dataRecoveryCertificate
      revokeOnUnenrollDisabled = $policy.revokeOnUnenrollDisabled
      azureRightsManagementServicesAllowed = $policy.azureRightsManagementServicesAllowed
      iconsVisible = $policy.iconsVisible
      daysWithoutContactBeforeUnenroll = $policy.daysWithoutContactBeforeUnenroll
    }
  }
}catch{"There was an error connecting to MS Graph for deviceAppManagement/windowsInformationProtectionPolicies"}

##Windows Information Protection-WithEnrollment#### 
try{
$AllWindowsInfoProtectionE = ""
  $AllWindowsInfoProtectionE = (Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mdmWindowsInformationProtectionPolicies" -Headers $Headers -Method Get -ContentType "application/json").value | Select-Object * -ExcludeProperty roleScopeTagIds,version,mdmEnrollmentUrl
  
  $WinInfoProtectEObj = foreach ($policy in $AllWindowsInfoProtectionE) {
    $policyInfo = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mdmWindowsInformationProtectionPolicies/$($policy.id)" -Headers $Headers -Method Get -ContentType "application/json" | Select-Object id, displayName, protectedApps, exemptApps
  
    [PSCustomObject]@{
      id   = $policyInfo.id
      displayName = $policyInfo.displayName
      managementType = "With Enrollment"
      createdDateTime  =$policy.createdDateTime
      lastModifiedDateTime = $policy.lastModifiedDateTime
      enforcementLevel = $policy.enforcementLevel
      enterpriseDomain  =$policy.enterpriseDomain
      protectedApps = $policyInfo.protectedApps.displayName -join(" ")
      exemptApps = $policyInfo.exemptApps.displayName -join(" ")
      isAssigned = $policy.isAssigned
      protectionUnderLockConfigRequired = $policy.protectionUnderLockConfigRequired
      dataRecoveryCertificate = $policy.dataRecoveryCertificate
      revokeOnUnenrollDisabled = $policy.revokeOnUnenrollDisabled
      azureRightsManagementServicesAllowed = $policy.azureRightsManagementServicesAllowed
      iconsVisible = $policy.iconsVisible
      daysWithoutContactBeforeUnenroll = $policy.daysWithoutContactBeforeUnenroll
    }
  }
}catch{"There was an error connecting to MS Graph for deviceAppManagement/mdmWindowsInformationProtectionPolicies"}

##IOS App Protection#### 
try{
  Write-Host "Getting iOS App protection Policies" -ForegroundColor Green
  $AlliOS = ""
  $AlliOS = (Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceAppManagement/iOSManagedAppProtections" -Headers $Headers -Method Get -ContentType "application/json").value | Select-Object * -ExcludeProperty version,roleScopeTagIds 
  
  $iOSAppProtectionObj = foreach ($policy in $AlliOS) {
    [PSCustomObject]@{
      displayName                                    = $policy.displayName
      description                                    = $policy.description
      createdDateTime                                = $policy.createdDateTime
      lastModifiedDateTime                           = $policy.lastModifiedDateTime
      id                                             = $policy.id  
      periodOfflineBeforeAccessCheck                 = $policy.periodOfflineBeforeAccessCheck
      periodOnlineBeforeAccessCheck                  = $policy.periodOnlineBeforeAccessCheck
      allowedInboundDataTransferSources              = $policy.allowedInboundDataTransferSources
      allowedOutboundDataTransferDestinations        = $policy.allowedOutboundDataTransferDestinations
      organizationalCredentialsRequired              = $policy.organizationalCredentialsRequired
      allowedOutboundClipboardSharingLevel           = $policy.allowedOutboundClipboardSharingLevel 
      dataBackupBlocked                              = $policy.dataBackupBlocked
      deviceComplianceRequired                       = $policy.deviceComplianceRequired 
      managedBrowserToOpenLinksRequired              = $policy.managedBrowserToOpenLinksRequired
      saveAsBlocked                                  = $policy.saveAsBlocked
      periodOfflineBeforeWipeIsEnforced              = $policy.periodOfflineBeforeWipeIsEnforced
      pinRequired                                    = $policy.pinRequired
      maximumPinRetries                              = $policy.maximumPinRetries
      simplePinBlocked                               = $policy.simplePinBlocked
      minimumPinLength                               = $policy.minimumPinLength
      pinCharacterSet                                = $policy.pinCharacterSet
      periodBeforePinReset                           = $policy.periodBeforePinReset
      allowedDataStorageLocations                    = $policy.allowedDataStorageLocations -join (", ")
      contactSyncBlocked                             = $policy.contactSyncBlocked
      printBlocked                                   = $policy.printBlocked
      fingerprintBlocked                             = $policy.fingerprintBlocked
      disableAppPinIfDevicePinIsSet                  = $policy.disableAppPinIfDevicePinIsSet
      maximumRequiredOsVersion                       = $policy.maximumRequiredOsVersion 
      maximumWarningOsVersion                        = $policy.maximumWarningOsVersion
      maximumWipeOsVersion                           = $policy.maximumWipeOsVersion
      minimumRequiredOsVersion                       = $policy.minimumRequiredOsVersion
      minimumWarningOsVersion                        = $policy.minimumWarningOsVersion
      minimumRequiredAppVersion                      = $policy.minimumRequiredAppVersion
      minimumWarningAppVersion                       = $policy.minimumWarningAppVersion
      minimumWipeOsVersion                           = $policy.minimumWipeOsVersion
      minimumWipeAppVersion                          = $policy.minimumWipeAppVersion
      appActionIfDeviceComplianceRequired            = $policy.appActionIfDeviceComplianceRequired
      appActionIfMaximumPinRetriesExceeded           = $policy.appActionIfMaximumPinRetriesExceeded
      pinRequiredInsteadOfBiometricTimeout           = $policy.pinRequiredInsteadOfBiometricTimeout 
      allowedOutboundClipboardSharingExceptionLength = $policy.allowedOutboundClipboardSharingExceptionLength
      notificationRestriction                        = $policy.notificationRestriction
      previousPinBlockCount                          = $policy.previousPinBlockCount
      managedBrowser                                 = $policy.managedBrowser
      maximumAllowedDeviceThreatLevel                = $policy.maximumAllowedDeviceThreatLevel 
      mobileThreatDefenseRemediationAction           = $policy.mobileThreatDefenseRemediationAction
      blockDataIngestionIntoOrganizationDocuments    = $policy.blockDataIngestionIntoOrganizationDocuments
      allowedDataIngestionLocations                  = $policy.allowedDataIngestionLocations -join (", ")
      appActionIfUnableToAuthenticateUser            = $policy.appActionIfUnableToAuthenticateUser
      dialerRestrictionLevel                         = $policy.dialerRestrictionLevel
      gracePeriodToBlockAppsDuringOffClockHours      = $policy.gracePeriodToBlockAppsDuringOffClockHours
      isAssigned                                     = $policy.isAssigned
      targetedAppManagementLevels                    = $policy.targetedAppManagementLevels
      appGroupType                                   = $policy.appGroupTyp
      appDataEncryptionType                          = $policy.appDataEncryptionType
      minimumRequiredSdkVersion                      = $policy.minimumRequiredSdkVersion
      deployedAppCount                               = $policy.deployedAppCount
      faceIdBlocked                                  = $policy.faceIdBlocked
      minimumWipeSdkVersion                          = $policy.minimumWipeSdkVersion
      allowedIosDeviceModels                         = $policy.allowedIosDeviceModels
      appActionIfIosDeviceModelNotAllowed            = $policy.appActionIfIosDeviceModelNotAllowed
      thirdPartyKeyboardsBlocked                     = $policy.thirdPartyKeyboardsBlocked
      filterOpenInToOnlyManagedApps                  = $policy.filterOpenInToOnlyManagedApps
      disableProtectionOfManagedOutboundOpenInData   = $policy.disableProtectionOfManagedOutboundOpenInData
      protectInboundDataFromUnknownSources           = $policy.protectInboundDataFromUnknownSources    
      customBrowserProtocol                          = $policy.customBrowserProtocol 
      customDialerAppProtocol                        = $policy.customDialerAppProtocol 
      managedUniversalLinks                          = $policy.managedUniversalLinks -join (", ")
      exemptedUniversalLinks                         = $policy.exemptedUniversalLinks -join (", ")
      exemptedAppProtocols                           = $policy.exemptedAppProtocols.name -join (", ")
  
    }
  }
}catch{"There was an error connecting to MS Graph for deviceAppManagement/iOSManagedAppProtections"}

##Android App Protection####  
try{
  Write-Host "Getting Android App protection Policies" -ForegroundColor Green
  $AllAndroid = ""
  $AllAndroid = (Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceAppManagement/androidManagedAppProtections" -Headers $Headers -Method Get -ContentType "application/json").value | Select-Object * -ExcludeProperty version 
  
  $AndroidAppProtectionObj = foreach ($policy in $AllAndroid) {
    [PSCustomObject]@{
  displayName                                        = $policy.displayName
  description                                        = $policy.description 
  createdDateTime                                    = $policy.createdDateTime
  lastModifiedDateTime                               = $policy.lastModifiedDateTime 
  id                                                 = $policy.id
  periodOfflineBeforeAccessCheck                     = $policy.periodOfflineBeforeAccessCheck
  periodOnlineBeforeAccessCheck                      = $policy.periodOnlineBeforeAccessCheck
  allowedInboundDataTransferSources                  = $policy.allowedInboundDataTransferSources
  allowedOutboundDataTransferDestinations            = $policy.allowedOutboundDataTransferDestinations 
  organizationalCredentialsRequired                  = $policy.organizationalCredentialsRequired
  allowedOutboundClipboardSharingLevel               = $policy.allowedOutboundClipboardSharingLevel
  dataBackupBlocked                                  = $policy.dataBackupBlocked  
  deviceComplianceRequired                           = $policy.deviceComplianceRequired
  managedBrowserToOpenLinksRequired                  = $policy.managedBrowserToOpenLinksRequired 
  saveAsBlocked                                      = $policy.saveAsBlocked 
  periodOfflineBeforeWipeIsEnforced                  = $policy.periodOfflineBeforeWipeIsEnforced
  pinRequired                                        = $policy.pinRequired  
  maximumPinRetries                                  = $policy.maximumPinRetries 
  simplePinBlocked                                   = $policy.simplePinBlocked 
  minimumPinLength                                   = $policy.minimumPinLength
  pinCharacterSet                                    = $policy.pinCharacterSet
  periodBeforePinReset                               = $policy.periodBeforePinReset  
  allowedDataStorageLocations                        = $policy.allowedDataStorageLocations  -join(" ")
  contactSyncBlocked                                 = $policy.contactSyncBlocked 
  printBlocked                                       = $policy.printBlocked  
  fingerprintBlocked                                 = $policy.fingerprintBlocked    
  disableAppPinIfDevicePinIsSet                      = $policy.disableAppPinIfDevicePinIsSet
  maximumRequiredOsVersion                           = $policy.maximumRequiredOsVersion 
  maximumWarningOsVersion                            = $policy.maximumWarningOsVersion
  maximumWipeOsVersion                               = $policy.maximumWipeOsVersion
  minimumRequiredOsVersion                           = $policy.minimumRequiredOsVersion
  minimumWarningOsVersion                            = $policy.minimumWarningOsVersion
  minimumRequiredAppVersion                          = $policy.minimumRequiredAppVersion 
  minimumWarningAppVersion                           = $policy.minimumWarningAppVersion
  minimumWipeOsVersion                               = $policy.minimumWipeOsVersion
  minimumWipeAppVersion                              = $policy.minimumWipeAppVersion
  appActionIfDeviceComplianceRequired                = $policy.appActionIfDeviceComplianceRequired 
  appActionIfMaximumPinRetriesExceeded               = $policy.appActionIfMaximumPinRetriesExceeded
  pinRequiredInsteadOfBiometricTimeout               = $policy.pinRequiredInsteadOfBiometricTimeout 
  allowedOutboundClipboardSharingExceptionLength     = $policy.allowedOutboundClipboardSharingExceptionLength
  notificationRestriction                            = $policy.notificationRestriction 
  previousPinBlockCount                              = $policy.previousPinBlockCount
  managedBrowser                                     = $policy.managedBrowser
  maximumAllowedDeviceThreatLevel                    = $policy.maximumAllowedDeviceThreatLevel
  mobileThreatDefenseRemediationAction               = $policy.mobileThreatDefenseRemediationAction
  blockDataIngestionIntoOrganizationDocuments        = $policy.blockDataIngestionIntoOrganizationDocuments
  allowedDataIngestionLocations                      = $policy.allowedDataIngestionLocations -join(" ")
  appActionIfUnableToAuthenticateUser                = $policy.appActionIfUnableToAuthenticateUser
  dialerRestrictionLevel                             = $policy.dialerRestrictionLevel   
  gracePeriodToBlockAppsDuringOffClockHours          = $policy.gracePeriodToBlockAppsDuringOffClockHours
  isAssigned                                         = $policy.isAssigned   
  targetedAppManagementLevels                        = $policy.targetedAppManagementLevels
  appGroupType                                       = $policy.appGroupType
  screenCaptureBlocked                               = $policy.screenCaptureBlocked
  disableAppEncryptionIfDeviceEncryptionIsEnabled    = $policy.disableAppEncryptionIfDeviceEncryptionIsEnabled
  encryptAppData                                     = $policy.encryptAppData
  deployedAppCount                                   = $policy.deployedAppCount
  minimumRequiredPatchVersion                        = $policy.minimumRequiredPatchVersion
  minimumWarningPatchVersion                         = $policy.minimumWarningPatchVersion
  minimumWipePatchVersion                            = $policy.minimumWipePatchVersion
  allowedAndroidDeviceManufacturers                  = $policy.allowedAndroidDeviceManufacturers
  appActionIfAndroidDeviceManufacturerNotAllowed     = $policy.appActionIfAndroidDeviceManufacturerNotAllowed
  requiredAndroidSafetyNetDeviceAttestationType      = $policy.requiredAndroidSafetyNetDeviceAttestationType
  appActionIfAndroidSafetyNetDeviceAttestationFailed = $policy.appActionIfAndroidSafetyNetDeviceAttestationFailed
  requiredAndroidSafetyNetAppsVerificationType       = $policy.requiredAndroidSafetyNetAppsVerificationType
  appActionIfAndroidSafetyNetAppsVerificationFailed  = $policy.appActionIfAndroidSafetyNetAppsVerificationFailed
  customBrowserPackageId                             = $policy.customBrowserPackageId
  customBrowserDisplayName                           = $policy.customBrowserDisplayName
  minimumRequiredCompanyPortalVersion                = $policy.minimumRequiredCompanyPortalVersion
  minimumWarningCompanyPortalVersion                 = $policy.minimumWarningCompanyPortalVersion
  minimumWipeCompanyPortalVersion                    = $policy.minimumWipeCompanyPortalVersion
  keyboardsRestricted                                = $policy.keyboardsRestricted
  allowedAndroidDeviceModels                         = $policy.allowedAndroidDeviceModels -join(" ")
  appActionIfAndroidDeviceModelNotAllowed            = $policy.appActionIfAndroidDeviceModelNotAllowed
  customDialerAppPackageId                           = $policy.customDialerAppPackageId
  customDialerAppDisplayName                         = $policy.customDialerAppDisplayName
  biometricAuthenticationBlocked                     = $policy.biometricAuthenticationBlocked
  requiredAndroidSafetyNetEvaluationType             = $policy.requiredAndroidSafetyNetEvaluationType
  blockAfterCompanyPortalUpdateDeferralInDays        = $policy.blockAfterCompanyPortalUpdateDeferralInDays
  warnAfterCompanyPortalUpdateDeferralInDays         = $policy.warnAfterCompanyPortalUpdateDeferralInDays
  wipeAfterCompanyPortalUpdateDeferralInDays         = $policy.wipeAfterCompanyPortalUpdateDeferralInDays
  deviceLockRequired                                 = $policy.deviceLockRequired
  appActionIfDeviceLockNotSet                        = $policy.appActionIfDeviceLockNotSet
  connectToVpnOnLaunch                               = $policy.connectToVpnOnLaunch
  exemptedAppPackages                                = $policy.exemptedAppPackages -join(" ")
  approvedKeyboards                                  = $policy.approvedKeyboards -join(" ")
  
    }
  }
}catch{"There was an error connecting to MS Graph for deviceAppManagement/androidManagedAppProtections"}

##Compliance Policies###
try{
Write-Host "Getting Compliance Policies" -ForegroundColor Green
$AllCompliancePolicies = ""
$AllCompliancePolicies = (Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies" -Headers $Headers -Method Get -ContentType "application/json").value 

##Win10 Compliance Policies

function Get-GroupNameFromId {
param (
    [Parameter()]
    $ID,

    [Parameter(Mandatory = $true)]
    $Groups
)
if ($id -eq 'All') {
    return 'All'
}
$DisplayName = $Groups | ? { $_.id -eq $ID } | Select -ExpandProperty DisplayName
if ([string]::IsNullOrEmpty($displayName)) {
    return "No Data"
}
else {
    return $DisplayName
}
}

function Get-IncludedGroups{
param (
    [Parameter()]
    $ID,
    [Parameter()]
    $path
)

$Assignments = (Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/$($path)/$($ID)/assignments" -Headers $Headers -Method Get -ContentType "application/json").value 
if($Assignments){

  $IncludedGroups = ($Assignments | Where-Object {$_.target.'@odata.type' -contains "#microsoft.graph.groupAssignmentTarget"}).target
  if($IncludedGroups){
    $IncludedGroups = ($IncludedGroups | % { Get-GroupNameFromId -Groups $GroupListOutput -id $_.groupId })
  } else{
    $IncludedGroups = ""
  }
  return $IncludedGroups
}
}
function Get-ExcludedGroups{
param (
    [Parameter()]
    $ID,
    [Parameter()]
    $path
    
)

$Assignments = (Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/$($path)/$($ID)/assignments" -Headers $Headers -Method Get -ContentType "application/json").value 
if($Assignments){

  $ExcludedGroups = ($Assignments | Where-Object {$_.target.'@odata.type' -contains "#microsoft.graph.exclusionGroupAssignmentTarget"}).target
  if($ExcludedGroups){
    $ExcludedGroups = ($ExcludedGroups | % { Get-GroupNameFromId -Groups $GroupListOutput -id $_.groupId })
  } else{
    $ExcludedGroups = ""
  }
  return $ExcludedGroups
}
}

$GroupListOutput = (Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/groups" -Headers $Headers -Method Get -ContentType "application/json").value

$Win10Compliance = $AllCompliancePolicies | Where-Object {$_."@odata.type" -eq "#microsoft.graph.windows10CompliancePolicy"} | Select-Object * -ExcludeProperty "@odata.type", roleScopeTagIds,version,validOperatingSystemBuildRanges 

$Win10ComplianceObj = foreach ($policy in $Win10Compliance) {
$Assignments = (Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies/$($policy.id)/assignments" -Headers $Headers -Method Get -ContentType "application/json").value 
$includedGroup = Get-IncludedGroups -id $policy.id -path "deviceManagement/deviceCompliancePolicies"
$ExcludedGroup = Get-ExcludedGroups -id $policy.id -path "deviceManagement/deviceCompliancePolicies"

[PSCustomObject]@{
    displayName                                 = $policy.displayName
    createdDateTime                             = $policy.createdDateTime
    description                                 = $policy.description
    IncludedGroups                              = if($Assignments| Where-Object {$_.target.'@odata.type' -contains "#microsoft.graph.allLicensedUsersAssignmentTarget"}){"All Users"}else{$IncludedGroup -join (",")}
    ExcludedGroups                              = $ExcludedGroup -join (",")
    lastModifiedDateTime                        = $policy.lastModifiedDateTime
    passwordRequired                            = $policy.passwordRequired
    passwordBlockSimple                         = $policy.passwordBlockSimple
    passwordRequiredToUnlockFromIdle            = $policy.passwordRequiredToUnlockFromIdle
    passwordMinutesOfInactivityBeforeLock       = $policy.passwordMinutesOfInactivityBeforeLock  
    passwordExpirationDays                      = $policy.passwordExpirationDays  
    passwordMinimumLength                       = $policy.passwordMinimumLength
    passwordMinimumCharacterSetCount            = $policy.passwordMinimumCharacterSetCount
    passwordRequiredType                        = $policy.passwordRequiredType
    passwordPreviousPasswordBlockCount          = $policy.passwordPreviousPasswordBlockCount
    requireHealthyDeviceReport                  = $policy.requireHealthyDeviceReport
    osMinimumVersion                            = $policy.osMinimumVersion  
    osMaximumVersion                            = $policy.osMaximumVersion 
    mobileOsMinimumVersion                      = $policy.mobileOsMinimumVersion 
    mobileOsMaximumVersion                      = $policy.mobileOsMaximumVersion 
    earlyLaunchAntiMalwareDriverEnabled         = $policy.earlyLaunchAntiMalwareDriverEnabled 
    bitLockerEnabled                            = $policy.bitLockerEnabled 
    secureBootEnabled                           = $policy.secureBootEnabled  
    codeIntegrityEnabled                        = $policy.codeIntegrityEnabled 
    storageRequireEncryption                    = $policy.storageRequireEncryption  
    activeFirewallRequired                      = $policy.activeFirewallRequired
    defenderEnabled                             = $policy.defenderEnabled
    defenderVersion                             = $policy.defenderVersion  
    signatureOutOfDate                          = $policy.signatureOutOfDate 
    rtpEnabled                                  = $policy.rtpEnabled 
    antivirusRequired                           = $policy.antivirusRequired 
    antiSpywareRequired                         = $policy.antiSpywareRequired 
    deviceThreatProtectionEnabled               = $policy.deviceThreatProtectionEnabled 
    deviceThreatProtectionRequiredSecurityLevel = $policy.deviceThreatProtectionRequiredSecurityLevel
    configurationManagerComplianceRequired      = $policy.configurationManagerComplianceRequired 
    tpmRequired                                 = $policy.tpmRequired
    deviceCompliancePolicyScript                = $policy.deviceCompliancePolicyScript 

}

}

##Android Compliance Policies

$AndroidCompliance = $AllCompliancePolicies | Where-Object {$_."@odata.type" -eq "#microsoft.graph.androidCompliancePolicy"} | Select-Object * -ExcludeProperty "@odata.type",roleScopeTagIds,version,validOperatingSystemBuildRanges 

$AndroidComplianceObj = foreach ($policy in $AndroidCompliance) {
$Assignments = (Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies/$($policy.id)/assignments" -Headers $Headers -Method Get -ContentType "application/json").value 

$includedGroup = Get-IncludedGroups -id $policy.id -path "deviceManagement/deviceCompliancePolicies"
$ExcludedGroup = Get-ExcludedGroups -id $policy.id -path "deviceManagement/deviceCompliancePolicies"

[PSCustomObject]@{
    displayName                                        = $policy.displayName
    createdDateTime                                    = $policy.createdDateTime
    lastModifiedDateTime                               = $policy.lastModifiedDateTime
    description                                        = $policy.description
    IncludedGroups                                     = if($Assignments| Where-Object {$_.target.'@odata.type' -contains "#microsoft.graph.allLicensedUsersAssignmentTarget"}){"All Users"}else{$IncludedGroup -join (",")}
    ExcludedGroups                                     = $ExcludedGroup -join (",")
    passwordRequired                                   = $policy.passwordRequired 
    passwordMinimumLength                              = $policy.passwordMinimumLength 
    passwordRequiredType                               = $policy.passwordRequiredType
    requiredPasswordComplexity                         = $policy.requiredPasswordComplexity   
    passwordMinutesOfInactivityBeforeLock              = $policy.passwordMinutesOfInactivityBeforeLock
    passwordExpirationDays                             = $policy.passwordExpirationDays  
    passwordPreviousPasswordBlockCount                 = $policy.passwordPreviousPasswordBlockCount     
    passwordSignInFailureCountBeforeFactoryReset       = $policy.passwordSignInFailureCountBeforeFactoryReset
    securityPreventInstallAppsFromUnknownSources       = $policy.securityPreventInstallAppsFromUnknownSources
    securityDisableUsbDebugging                        = $policy.securityDisableUsbDebugging 
    securityRequireVerifyApps                          = $policy.securityRequireVerifyApps 
    deviceThreatProtectionEnabled                      = $policy.deviceThreatProtectionEnabled 
    deviceThreatProtectionRequiredSecurityLevel        = $policy.deviceThreatProtectionRequiredSecurityLevel   
    advancedThreatProtectionRequiredSecurityLevel      = $policy.advancedThreatProtectionRequiredSecurityLevel 
    securityBlockJailbrokenDevices                     = $policy.securityBlockJailbrokenDevices 
    securityBlockDeviceAdministratorManagedDevices     = $policy.securityBlockDeviceAdministratorManagedDevices
    osMinimumVersion                                   = $policy.osMinimumVersion  
    osMaximumVersion                                   = $policy.osMaximumVersion      
    minAndroidSecurityPatchLevel                       = $policy.minAndroidSecurityPatchLevel   
    storageRequireEncryption                           = $policy.storageRequireEncryption   
    securityRequireSafetyNetAttestationBasicIntegrity  = $policy.securityRequireSafetyNetAttestationBasicIntegrity 
    securityRequireSafetyNetAttestationCertifiedDevice = $policy.securityRequireSafetyNetAttestationCertifiedDevice
    securityRequireGooglePlayServices                  = $policy.securityRequireGooglePlayServices   
    securityRequireUpToDateSecurityProviders           = $policy.securityRequireUpToDateSecurityProviders  
    securityRequireCompanyPortalAppIntegrity           = $policy.securityRequireCompanyPortalAppIntegrity  
    conditionStatementId                               = $policy.conditionStatementId   
    restrictedApps                                     = $policy.restrictedApps -join(" ")

}

}

##iOS Compliance Policies

$iOSCompliance = $AllCompliancePolicies | Where-Object {$_."@odata.type" -eq "#microsoft.graph.iOSCompliancePolicy"} | Select-Object * -ExcludeProperty "@odata.type",roleScopeTagIds,version,validOperatingSystemBuildRanges 

$iOSComplianceObj = foreach ($policy in $iOSCompliance) {
$Assignments = (Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies/$($policy.id)/assignments" -Headers $Headers -Method Get -ContentType "application/json").value 
$includedGroup = Get-IncludedGroups -id $policy.id -path "deviceManagement/deviceCompliancePolicies"
$ExcludedGroup = Get-ExcludedGroups -id $policy.id -path "deviceManagement/deviceCompliancePolicies"

[PSCustomObject]@{
    displayName                                        = $policy.displayName
    createdDateTime                                    = $policy.createdDateTime
    lastModifiedDateTime                               = $policy.lastModifiedDateTime
    description                                        = $policy.description
    IncludedGroups                                     = if($Assignments| Where-Object {$_.target.'@odata.type' -contains "#microsoft.graph.allLicensedUsersAssignmentTarget"}){"All Users"}else{$IncludedGroup -join (",")}
    ExcludedGroups                                     = $ExcludedGroup -join (",")
    passcodeBlockSimple                                = $policy.passcodeBlockSimple
    passcodeExpirationDays                             = $policy.passcodeExpirationDays 
    passcodeMinimumLength                              = $policy.passcodeMinimumLength
    passcodeMinutesOfInactivityBeforeLock              = $policy.passcodeMinutesOfInactivityBeforeLock
    passcodeMinutesOfInactivityBeforeScreenTimeout     = $policy.passcodeMinutesOfInactivityBeforeScreenTimeout
    passcodePreviousPasscodeBlockCount                 = $policy.passcodePreviousPasscodeBlockCount 
    passcodeMinimumCharacterSetCount                   = $policy.passcodeMinimumCharacterSetCount  
    passcodeRequiredType                               = $policy.passcodeRequiredType
    passcodeRequired                                   = $policy.passcodeRequired 
    osMinimumVersion                                   = $policy.osMinimumVersion  
    osMaximumVersion                                   = $policy.osMaximumVersion 
    osMinimumBuildVersion                              = $policy.osMinimumBuildVersion 
    osMaximumBuildVersion                              = $policy.osMaximumBuildVersion  
    securityBlockJailbrokenDevices                     = $policy.securityBlockJailbrokenDevices  
    deviceThreatProtectionEnabled                      = $policy.deviceThreatProtectionEnabled
    deviceThreatProtectionRequiredSecurityLevel        = $policy.deviceThreatProtectionRequiredSecurityLevel
    advancedThreatProtectionRequiredSecurityLevel      = $policy.advancedThreatProtectionRequiredSecurityLevel 
    managedEmailProfileRequired                        = $policy.managedEmailProfileRequired
    restrictedApps                                     = $policy.restrictedApps -join(" ")

}

}


##macOS Compliance Policies

$macOSCompliance = $AllCompliancePolicies | Where-Object {$_."@odata.type" -eq "#microsoft.graph.macOSCompliancePolicy"} | Select-Object * -ExcludeProperty "@odata.type",roleScopeTagIds,version,validOperatingSystemBuildRanges 

$macOSComplianceObj = foreach ($policy in $macOSCompliance) {
$Assignments = (Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies/$($policy.id)/assignments" -Headers $Headers -Method Get -ContentType "application/json").value 
$includedGroup = Get-IncludedGroups -id $policy.id -path "deviceManagement/deviceCompliancePolicies"
$ExcludedGroup = Get-ExcludedGroups -id $policy.id -path "deviceManagement/deviceCompliancePolicies"

[PSCustomObject]@{
  displayName                                        = $policy.displayName
  createdDateTime                                    = $policy.createdDateTime
  lastModifiedDateTime                               = $policy.lastModifiedDateTime
  description                                        = $policy.description
  IncludedGroups                                     = if($Assignments| Where-Object {$_.target.'@odata.type' -contains "#microsoft.graph.allLicensedUsersAssignmentTarget"}){"All Users"}else{$IncludedGroup -join (",")}
  ExcludedGroups                                     = $ExcludedGroup -join (",")
  passwordRequired                                   = $policy.passwordRequired
  passwordBlockSimple                                = $policy.passwordBlockSimple 
  passwordExpirationDays                             = $policy.passwordExpirationDays
  passwordMinimumLength                              = $policy.passwordMinimumLength
  passwordMinutesOfInactivityBeforeLock              = $policy.passwordMinutesOfInactivityBeforeLock 
  passwordPreviousPasswordBlockCount                 = $policy.passwordPreviousPasswordBlockCount 
  passwordMinimumCharacterSetCount                   = $policy.passwordMinimumCharacterSetCount
  passwordRequiredType                               = $policy.passwordRequiredType 
  osMinimumVersion                                   = $policy.osMinimumVersion
  osMaximumVersion                                   = $policy.osMaximumVersion 
  osMinimumBuildVersion                              = $policy.osMinimumBuildVersion
  osMaximumBuildVersion                              = $policy.osMaximumBuildVersion
  systemIntegrityProtectionEnabled                   = $policy.systemIntegrityProtectionEnabled
  deviceThreatProtectionEnabled                      = $policy.deviceThreatProtectionEnabled 
  deviceThreatProtectionRequiredSecurityLevel        = $policy.deviceThreatProtectionRequiredSecurityLevel
  advancedThreatProtectionRequiredSecurityLevel      = $policy.advancedThreatProtectionRequiredSecurityLevel
  storageRequireEncryption                           = $policy.storageRequireEncryption 
  gatekeeperAllowedAppSource                         = $policy.gatekeeperAllowedAppSource
  firewallEnabled                                    = $policy.firewallEnabled
  firewallBlockAllIncoming                           = $policy.firewallBlockAllIncoming
  firewallEnableStealthMode                          = $policy.firewallEnableStealthMode

} 
}
}catch{"There was an error connecting to MS Graph for deviceManagement/deviceCompliancePolicies"}

##Configuration Profiles
try{
Write-Host "Getting Configuration Profiles" -ForegroundColor Green
$ConfigProfiles = (Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations" -Headers $Headers -Method Get -ContentType "application/json").value | Select-Object "@odata.type", id, displayName,description, createdDateTime,lastModifiedDateTime

$GroupPolicyProfiles  = (Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations" -Headers $Headers -Method Get -ContentType "application/json").value | Select-Object id, displayName,description, createdDateTime,lastModifiedDateTime

$ConfigProfileObj = foreach ($policy in $ConfigProfiles) {
$Assignments = (Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$($policy.id)/assignments" -Headers $Headers -Method Get -ContentType "application/json").value 
$includedGroup = Get-IncludedGroups -id $policy.id -path "deviceManagement/deviceConfigurations"
$ExcludedGroup = Get-ExcludedGroups -id $policy.id -path "deviceManagement/deviceConfigurations"
$AllDevices = ($Assignments | Where-Object {$_.target.'@odata.type' -contains "#microsoft.graph.allDevicesAssignmentTarget"})
if($AllDevices){
  $AllDevices = "All Devices"
}
$AllUsers = ($Assignments | Where-Object {$_.target.'@odata.type' -contains "#microsoft.graph.allLicensedUsersAssignmentTarget"})
if($AllUsers){
  $AllUsers = "All Users"
}
[PSCustomObject]@{
  Type                                               = $policy."@odata.type".split('.')[2]
  displayName                                        = $policy.displayName
  createdDateTime                                    = $policy.createdDateTime
  lastModifiedDateTime                               = $policy.lastModifiedDateTime
  description                                        = $policy.description
  IncludedGroups                                     = if($AllDevices -and $AllUsers){$AllUsers, $AllDevices -Join (",")}elseif($AllDevices){$AllDevices}elseif($AllUsers){$AllUsers}else{$IncludedGroup -join (",")}
  ExcludedGroups                                     = $ExcludedGroup -join (",")
 
}

}

$GroupPolicyObj = foreach ($policy in $GroupPolicyProfiles) {
$Assignments = (Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/$($policy.id)/assignments" -Headers $Headers -Method Get -ContentType "application/json").value 
$includedGroup = Get-IncludedGroups -id $policy.id -path "deviceManagement/groupPolicyConfigurations"
$ExcludedGroup = Get-ExcludedGroups -id $policy.id -path "deviceManagement/groupPolicyConfigurations"
$AllDevices = ($Assignments | Where-Object {$_.target.'@odata.type' -contains "#microsoft.graph.allDevicesAssignmentTarget"})
if($AllDevices){
  $AllDevices = "All Devices"
}
$AllUsers = ($Assignments | Where-Object {$_.target.'@odata.type' -contains "#microsoft.graph.allLicensedUsersAssignmentTarget"})
if($AllUsers){
  $AllUsers = "All Users"
} 

[PSCustomObject]@{
  Type                                               = "Administrative Template"
  displayName                                        = $policy.displayName
  createdDateTime                                    = $policy.createdDateTime
  lastModifiedDateTime                               = $policy.lastModifiedDateTime
  description                                        = $policy.description
  IncludedGroups                                     = if($AllDevices -and $AllUsers){"All Users and All Devices"}elseif($AllDevices){$AllDevices}elseif($AllUsers){$AllUsers}else{$IncludedGroup -join (",")}
  ExcludedGroups                                     = $ExcludedGroup -join (",")
 
}
}
}catch{"There was an error connecting to MS Graph for deviceManagement/deviceConfigurations"}

###GET APPS

function Get-Assignments{
  param (
      [Parameter()]
      $ID,
      [Parameter()]
      $Intent
  )

  $Assignments = (Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($ID)/assignments" -Headers $Headers -Method Get -ContentType "application/json").value 

  $AssignmentType = ($Assignments | Where-Object {$_.intent -contains $Intent}).target
  if($AssignmentType){
    if($AssignmentType.'@odata.type' -eq "#microsoft.graph.allDevicesAssignmentTarget"){
      $output = "All Devices"
    }elseif ($AssignmentType.'@odata.type' -eq "#microsoft.graph.groupAssignmentTarget") {
      $output = ($AssignmentType |  % { Get-GroupNameFromId -Groups $GroupListOutput -id $_.groupId })
    } else {
      $output = "N/A"
    }
    return $output
  }
}

function Get-AppAssignments{
  param (
      [Parameter()]
      $ID
  )
    $AppAssignments = [PSCustomObject]@{
      required    = Get-Assignments -id $ID -Intent "required"
      available   = Get-Assignments -id $ID -Intent "available"
      uninstall   = Get-Assignments -id $ID -Intent "uninstall"
      availableWithoutEnrollment   = Get-Assignments -id $ID -Intent "availableWithoutEnrollment"
    }

    return $AppAssignments
  }


$GroupListOutput = (Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/groups" -Headers $Headers -Method Get -ContentType "application/json").value

try{
   Write-Host "Getting Intune Apps" -ForegroundColor Green
    $filters= "microsoft.graph.managedApp/appAvailability eq null or microsoft.graph.managedApp/appAvailability eq 'lineOfBusiness' or isAssigned eq true"
    $uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?filter=$($filters)"
    $Apps = (Invoke-RestMethod -Uri $uri -Headers $Headers -Method Get -ContentType "application/json").value | Select-Object '@odata.type', id, displayName,publisher, createdDateTime,lastModifiedDateTime, isAssigned
    
    
    $AppObj = foreach ($app in $Apps) {
      $AppAssign = Get-AppAssignments -ID $app.id
    
      [PSCustomObject]@{
        Type                                               = $app.'@odata.type'.split(".")[2]
        displayName                                        = $app.displayName
        publisher                                          = $app.publisher -join(" ")
        createdDateTime                                    = $app.createdDateTime
        lastModifiedDateTime                               = $app.lastModifiedDateTime
        required                                           = $AppAssign.required
        available                                          = $AppAssign.available
        availableWithoutEnrollment                         = $AppAssign. availableWithoutEnrollment
        uninstall                                          = $AppAssign.uninstall
       
    }
    }
}catch{"There was an error connecting to MS Graph for deviceAppManagement/mobileApps"}


###App Configuration Profiles####
try{
    Write-Host "Getting App Configuration Profiles" -ForegroundColor Green
    $MobileAppConfig = (Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileAppConfigurations" -Headers $Headers -Method Get -ContentType "application/json").value
  
    $MobileApps = (Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps" -Headers $Headers -Method Get -ContentType "application/json").value
  
   $TargetedManagedApps = (Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceAppManagement/targetedManagedAppConfigurations" -Headers $Headers -Method Get -ContentType "application/json").value

   function Get-TargetedMobileApps {
      param (
        [Parameter()]
          $ID
      )
    
      $AppName = (Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($ID)" -Headers $Headers -Method Get -ContentType "application/json").displayName
      
      return $AppName
    }
    
    $MobileAppConfigObj = foreach ($policy in $MobileAppConfig) {
      $targetedApps = ($policy | % {Get-TargetedMobileApps -id $_.targetedMobileApps} )
      $Assignments = (Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileAppConfigurations/$($policy.id)/assignments" -Headers $Headers -Method Get -ContentType "application/json").value 
      $includedGroup = Get-IncludedGroups -id $policy.id -path "deviceAppManagement/mobileAppConfigurations"
      $ExcludedGroup = Get-ExcludedGroups -id $policy.id -path "deviceAppManagement/mobileAppConfigurations"
      $AllDevices = ($Assignments | Where-Object {$_.target.'@odata.type' -contains "#microsoft.graph.allDevicesAssignmentTarget"})
      if($AllDevices){
        $AllDevices = "All Devices"
      }
      $AllUsers = ($Assignments | Where-Object {$_.target.'@odata.type' -contains "#microsoft.graph.allLicensedUsersAssignmentTarget"})
      if($AllUsers){
        $AllUsers = "All Users"
      }
      [PSCustomObject]@{
        displayName                                        = $policy.displayName
        createdDateTime                                    = $policy.createdDateTime
        lastModifiedDateTime                               = $policy.lastModifiedDateTime
        targetedApps                                       = $targetedApps
        xmlconfig                                          = if($policy.encodedSettingXml){$true}else{$false}
        appConfigKey                                       = if($policy.settings){$policy.settings.appConfigKey}else{"N/A"}
        appConfigKeyType                                   = if($policy.settings){$policy.settings.appConfigKeyType}else{"N/A"}
        appConfigKeyValue                                  = if($policy.settings){$policy.settings.appConfigKeyValue}else{"N/A"}
        IncludedGroups                                     = if($AllDevices -and $AllUsers){"All Users and Devices"}elseif($AllDevices){$AllDevices}elseif($AllUsers){$AllUsers}else{$IncludedGroup -join (",")}
        ExcludedGroups                                     = $ExcludedGroup -join (",")
      }
      
    }
    
    $TargetedAppObj = foreach ($policy in $TargetedManagedApps) {
    
      $Assignments = (Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceAppManagement/targetedManagedAppConfigurations/$($policy.id)/assignments" -Headers $Headers -Method Get -ContentType "application/json").value 
      $includedGroup = Get-IncludedGroups -id $policy.id -path "deviceAppManagement/targetedManagedAppConfigurations"
      $ExcludedGroup = Get-ExcludedGroups -id $policy.id -path "deviceAppManagement/targetedManagedAppConfigurations"
      
      [PSCustomObject]@{
        displayName                                        = $policy.displayName
        description                                        = $policy.description
        createdDateTime                                    = $policy.createdDateTime
        lastModifiedDateTime                               = $policy.lastModifiedDateTime
        appGroupType                                       = $policy.appGroupType
        customSettings                                     = $policy.customSettings -join (",")
        IncludedGroups                                     = $IncludedGroup -join (",")
        ExcludedGroups                                     = $ExcludedGroup -join (",")
      }
      
    }

}catch{"There was an error connecting to MS Graph for deviceAppManagement/mobileAppConfigurations"}
$FlexAssetBody = 
@{
    type       = "flexible-assets"
    attributes = @{
        traits = @{
            "customer-name"                                = $customer.Name
            "windows-compliance-policies"                 = ($Win10ComplianceObj | convertto-html -Fragment  | out-string)
            "macos-compliance-policies"                   = ($macOSComplianceObj | convertto-html -Fragment | out-string)
            "ios-compliance-policies"                     = ($iOSComplianceObj | convertto-html -Fragment  | out-string)
            "android-compliance-policies"                 = ($AndroidComplianceObj | convertto-html -Fragment  | out-string)
            "configuration-profiles"                      = ($ConfigProfileObj | convertto-html -Fragment  | out-string)
            "group-policy"                                = ($GroupPolicyObj | convertto-html -Fragment  | out-string)
            "applications"                                = ($AppObj | convertto-html -Fragment  | out-string)
            "wip-without-enrollment"                      = ($WinInfoProtectWEObj | convertto-html -Fragment  | out-string)
            "wip-with-enrollment"                         = ($WinInfoProtectEObj | convertto-html -Fragment  | out-string)
            "ios-app-protection-policies"                 = ($iOSAppProtectionObj | convertto-html -Fragment  | out-string)
            "android-app-protection-policies"             = ($AndroidAppProtectionObj | convertto-html -Fragment  | out-string)
            "managed-app-configuration-policies"          = ($MobileAppConfigObj | convertto-html -Fragment  | out-string)
            "managed-device-app-configuration-policies"   = ($TargetedAppObj| convertto-html -Fragment  | out-string)
                                 
        }
    }
}

 $ExistingFlexAsset = (Get-ITGlueFlexibleAssets -filter_flexible_asset_type_id $($filterID.id) -filter_organization_id $orgID).data | Where-Object { $_.attributes.traits.'customer-name' -eq $customer.name}
#If the Asset does not exist, we edit the body to be in the form of a new asset, if not, we just update.
if (!$ExistingFlexAsset) {
    $FlexAssetBody.attributes.add('organization-id', $orgID)
    $FlexAssetBody.attributes.add('flexible-asset-type-id', $($filterID.ID))
    write-host "Creating Intune setings for $($customer.name) into IT-Glue" -ForegroundColor Green
    New-ITGlueFlexibleAssets -data $FlexAssetBody
}
else {
    write-host "Updating Intune Settings  for $($customer.name) into IT-Glue"  -ForegroundColor Yellow
    $ExistingFlexAsset = $ExistingFlexAsset | select-object -last 1
    Set-ITGlueFlexibleAssets -id $ExistingFlexAsset.id -data $FlexAssetBody
}


}
}