<#
  .SYNOPSIS
  This script is used to garner Intune information across all customers and output that information to a CSV file
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
        [string]$refreshToken
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
$TargetedAppObj = ""


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


##GET DOMAIN 
$customerDomain = (Get-MsolDomain -TenantId $customer.TenantID).name[1]

#Define CSV Path 
$path = echo ([Environment]::GetFolderPath("Desktop")+"\Microsoft_${customerDomain}_OrgReports")
New-Item -ItemType Directory -Force -Path $path
##WIP WithoutEnrollment CSV Path
if($WinInfoProtectWEObj){
  $WIPWithoutEnrollReport = echo ([Environment]::GetFolderPath("Desktop")+"\Microsoft_${customerDomain}_OrgReports\WIPWithoutEnroll.csv")
  $WinInfoProtectWEObj | Export-CSV -Path $WIPWithoutEnrollReport  -NoTypeInformation -Append
  }
  ##WIP WithEnrollment CSV Path
  if($WinInfoProtectEObj){
  $WIPWithEnrollReport = echo ([Environment]::GetFolderPath("Desktop")+"\Microsoft_${customerDomain}_OrgReports\WIPWithEnroll.csv")
  $WinInfoProtectEObj | Export-CSV -Path $WIPWithEnrollReport  -NoTypeInformation -Append
  }
  ##iOS App Protection CSV Path
  if($iOSAppProtectionObj){
  $iOSAppProtectReport = echo ([Environment]::GetFolderPath("Desktop")+"\Microsoft_${customerDomain}_OrgReports\iOSAppProtect.csv")
  $iOSAppProtectionObj | Export-CSV -Path $iOSAppProtectReport  -NoTypeInformation -Append
  }
  ##Android App Protection CSV Path
  if($AndroidAppProtectionObj){
  $AndroidAppProtectReport = echo ([Environment]::GetFolderPath("Desktop")+"\Microsoft_${customerDomain}_OrgReports\AndroidAppProtect.csv")
  $AndroidAppProtectionObj | Export-CSV -Path $AndroidAppProtectReport  -NoTypeInformation -Append
  }
  ##macOS Compliance CSV Path
  if($macOSComplianceObj){
  $macOSComplianceReport = echo ([Environment]::GetFolderPath("Desktop")+"\Microsoft_${customerDomain}_OrgReports\macOSCompliance.csv")
  $macOSComplianceObj | Export-CSV -Path $macOSComplianceReport  -NoTypeInformation -Append
  }
  ##iOS Compliance CSV Path
  if($iOSComplianceObj){
  $iOSComplianceReport = echo ([Environment]::GetFolderPath("Desktop")+"\Microsoft_${customerDomain}_OrgReports\iOSCompliance.csv")
  $iOSComplianceObj | Export-CSV -Path $iOSComplianceReport  -NoTypeInformation -Append
  }
  ##Android Compliance CSV Path
  if($AndroidComplianceObj){
  $AndroidComplianceReport = echo ([Environment]::GetFolderPath("Desktop")+"\Microsoft_${customerDomain}_OrgReports\AndroidCompliance.csv")
  $AndroidComplianceObj | Export-CSV -Path $AndroidComplianceReport  -NoTypeInformation -Append
  }
  ##Windows Compliance CSV Path
  if($Win10ComplianceObj){
  $Win10ComplianceReport = echo ([Environment]::GetFolderPath("Desktop")+"\Microsoft_${customerDomain}_OrgReports\Win10Compliance.csv")
  $Win10ComplianceObj | Export-CSV -Path $Win10ComplianceReport  -NoTypeInformation -Append
  }
  ##Administrative Templates CSV Path
  if($GroupPolicyObj){
  $AdminTemplatesReport = echo ([Environment]::GetFolderPath("Desktop")+"\Microsoft_${customerDomain}_OrgReports\AdminTemplates.csv")
  $GroupPolicyObj | Export-CSV -Path $AdminTemplatesReport  -NoTypeInformation -Append
  }
  ##Configuration Profiles CSV Path
  if($ConfigProfileObj){
  $ConfigProfilesReport = echo ([Environment]::GetFolderPath("Desktop")+"\Microsoft_${customerDomain}_OrgReports\ConfigProfiles.csv")
  $ConfigProfileObj  | Export-CSV -Path $ConfigProfilesReport  -NoTypeInformation -Append
  }
  ##Intune Apps CSV Path
  if($AppObj){
  $IntuneAppsReport = echo ([Environment]::GetFolderPath("Desktop")+"\Microsoft_${customerDomain}_OrgReports\IntuneApps.csv")
  $AppObj | Export-CSV -Path $IntuneAppsReport  -NoTypeInformation -Append
  }
  ##App Config Managed Devices CSV Path
  if($MobileAppConfigObj){
  $AppConfigManagedDevicesReport = echo ([Environment]::GetFolderPath("Desktop")+"\Microsoft_${customerDomain}_OrgReports\AppConfigManagedDevices.csv")
  $MobileAppConfigObj | Export-CSV -Path $AppConfigManagedDevicesReport  -NoTypeInformation -Append
  }
  ##App Config Managed Apps CSV Path
  if($TargetedAppObj){
  $AppConfigManagedAppsReport = echo ([Environment]::GetFolderPath("Desktop")+"\Microsoft_${customerDomain}_OrgReports\AppConfigManagedApps.csv")
  $TargetedAppObj | Export-CSV -Path $AppConfigManagedAppsReport  -NoTypeInformation -Append
  }


cd $path;

# Grab CSVs, Count, and write to console
$csvs = Get-ChildItem .\* -Include *.csv
$y=$csvs.Count
Write-Host "Detected the following CSV files: ($y)"

# Write CSV file name to oncsole
foreach ($csv in $csvs)
{ Write-Host " "$csv.Name }

# Grab export file and write to console
$outputfilename = "$path\$(${customerDomain})_OrgSettgings.xlsx"
Write-Host Creating: $outputfilename

# Declare and instantiate excel object, declare number of sheets by csv file name count, use .Add method to add the sheets, set sheet=1 as a counter
$excelapp = new-object -comobject Excel.Application
$excelapp.sheetsInNewWorkbook = $csvs.Count
$xlsx = $excelapp.Workbooks.Add()
$sheet=1

foreach ($csv in $csvs)
{
	$row=1
	$column=1
	$worksheet = $xlsx.Worksheets.Item($sheet)
	$worksheet.Name = $csv.Name
	$file = (Get-Content $csv)
	foreach($line in $file)
	{
		$linecontents=$line -split ',(?!\s*\w+")'
		foreach($cell in $linecontents)
		{
  
			$worksheet.Cells.Item($row,$column) =  $cell.trim("`"") 
			$column++
		}
		$column=1
		$row++
	}
    $usedrange = $worksheet.UsedRange
    $usedrange.entireColumn.AutoFit() | out-null
	$sheet++
}

#Output
$xlsx.SaveAs($outputfilename)
$excelapp.quit()
}