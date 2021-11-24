<#
  .SYNOPSIS
  This script is used to garner user information from a single Microsoft Tenant and add that information as a flexible assets in IT Glue
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
        [Parameter(Mandatory= $true, HelpMessage="Enter your Exchange refreshToken from the Secure Application Model")]
        [string]$ExchangeRefreshToken,
        [Parameter(Mandatory= $true, HelpMessage="Enter your Partner Center UPN")]
        [string]$upn,
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
$ExchangeRefreshToken = $ExchangeRefreshToken
$upn = $upn
$secPas = $ApplicationSecret| ConvertTo-SecureString -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($ApplicationId, $secPas)


########################## IT-Glue Information ############################
$APIKey = $ITGlueAPIKey
$APIEndpoint = "https://api.itglue.com"
$FlexAssetName = "Exchange Settings"
$Description = "Documentation for all Exchange Related Settings"

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
            icon        = 'mail'
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
                            name            = "Legacy Auth Settings"
                            kind            = "Textbox"
                            required        = $false
                            "show-in-list"  = $true
                        }
                    },

                    @{
                        type       = "flexible_asset_fields"
                        attributes = @{
                            order          = 3
                            name           = "Mail Transport Rules"
                            kind           = "Textbox"
                            required       = $false 
                            "show-in-list" = $true
                        }
                    }
                    @{
                        type       = "flexible_asset_fields"
                        attributes = @{
                            order          = 4
                            name           = "OWA Policies"
                            kind           = "Textbox"
                            required       = $false
                            "show-in-list" = $true
                        }
                    }
                    @{
                        type       = "flexible_asset_fields"
                        attributes = @{
                            order          = 5
                            name           = "Accepted Domains"
                            kind           = "Textbox"
                            required       = $false
                            "show-in-list" = $true
                        }
                    }
                    @{
                        type       = "flexible_asset_fields"
                        attributes = @{
                            order          = 6
                            name           = "Journal Rules"
                            kind           = "Textbox"
                            required       = $false
                            "show-in-list" = $true
                        }
                    }
                    @{
                        type       = "flexible_asset_fields"
                        attributes = @{
                            order          = 7
                            name           = "Mobile Device Policy"
                            kind           = "Textbox"
                            required       = $false
                            "show-in-list" = $true
                        }
                    }
                    @{
                        type       = "flexible_asset_fields"
                        attributes = @{
                            order          = 8
                            name           = "Retention Policy"
                            kind           = "Textbox"
                            required       = $false
                            "show-in-list" = $true
                        }
                    }
                    @{
                        type       = "flexible_asset_fields"
                        attributes = @{
                            order          = 9
                            name           = "Retention Policy Tags"
                            kind           = "Textbox"
                            required       = $false
                            "show-in-list" = $true
                        }
                    }
                    @{
                        type       = "flexible_asset_fields"
                        attributes = @{
                            order          = 10
                            name           = "Antiphishing Polciies"
                            kind           = "Textbox"
                            required       = $false
                            "show-in-list" = $true
                        }
                    }
                    @{
                        type       = "flexible_asset_fields"
                        attributes = @{
                            order          = 11
                            name           = "Outbound Spam Policy"
                            kind           = "Textbox"
                            required       = $false
                            "show-in-list" = $true
                        }
                    }
                    @{
                        type       = "flexible_asset_fields"
                        attributes = @{
                            order          = 12
                            name           = "AntiSpam Policies"
                            kind           = "Textbox"
                            required       = $false
                            "show-in-list" = $true
                        }
                    }
                    @{
                        type       = "flexible_asset_fields"
                        attributes = @{
                            order          = 13
                            name           = "Antimalware Policies"
                            kind           = "Textbox"
                            required       = $false
                            "show-in-list" = $true
                        }
                    }
                    @{
                        type       = "flexible_asset_fields"
                        attributes = @{
                            order          = 14
                            name           = "Safe Attachment Policies"
                            kind           = "Textbox"
                            required       = $false
                            "show-in-list" = $true
                        }
                    }
                    @{
                        type       = "flexible_asset_fields"
                        attributes = @{
                            order          = 15
                            name           = "Safe Links Policies"
                            kind           = "Textbox"
                            required       = $false
                            "show-in-list" = $true
                        }
                    }
                    @{
                      type       = "flexible_asset_fields"
                      attributes = @{
                          order          = 16
                          name           = "DKIM"
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

$LegacyAuthSettings = "" 	
$TransportRule = ""
$OWAPolicyObj = ""
$AcceptedDomains = ""
$MobileDevicePolicyObj = ""
$RetentionPolicy = ""
$RetentionPolicyTags = ""
$JournalRules = ""
$AntiphishObj = ""
$OutboundSpam = ""
$AntiSpamObj = ""
$malwareObj = "" 
$SafeAttachmentObj = ""
$SafeLinkObj = ""
$DKIM = ""

$CustomerDomains = Get-MsolDomain -TenantId $customer.TenantID
$orgid = foreach ($customerDomain in $customerdomains) {
    ($domainList | Where-Object { $_.domain -eq $customerDomain.name }).'OrgID'
}

$orgID = $orgid | Select-Object -Unique
if(!$orgID){
   Write-Host "Customer does not exist in IT-Glue" -ForegroundColor Red
}

if($orgid){

  ### Connect to Exchange
  Write-Host "Connecting to Exchange" -ForegroundColor Green
  $token = New-PartnerAccessToken -ApplicationId 'a0c73c16-a7e3-4564-9a95-2bdf47383716'-RefreshToken $ExchangeRefreshToken -Scopes 'https://outlook.office365.com/.default' -Tenant $customer.TenantId
  $tokenValue = ConvertTo-SecureString "Bearer $($token.AccessToken)" -AsPlainText -Force
  $credential = New-Object System.Management.Automation.PSCredential($upn, $tokenValue)
  $customerId = $customer.DefaultDomainName
  $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "https://ps.outlook.com/powershell-liveid?DelegatedOrg=$($customerId)&BasicAuthToOAuthConversion=true" -Credential $credential -Authentication Basic -AllowRedirection
  Import-PSSession $session
  
  if($session){
  
      ##Get Mail Rules
   Write-Host "Getting Transport Rules" -ForegroundColor Green
   $TransportRule = Get-TransportRule | Select-Object Name, State, Mode, Priority
  
  
   ##Get Outlook Web App Policies
   Write-Host "Getting OWA Policies" -ForegroundColor Green
   $OWAPolicies = Get-OwaMailboxPolicy | Select-Object Identity, IsDefault, InstantMessagingEnabled,TextMessagingEnabled,ActiveSyncIntegrationEnabled,ContactsEnabled,AllowCopyContactsToDeviceAddressBook,LinkedInEnabled,AllAddressListsEnabled,JournalEnabled,NotesEnabled,RulesEnabled,RecoverDeletedItemsEnabled,ThemeSelectionEnabled,PremiumClientEnabled,SignaturesEnabled,WeatherEnabled,PlacesEnabled,LocalEventsEnabled,InterestingCalendarsEnabled,CalendarEnabled,TasksEnabled,RemindersAndNotificationsEnabled,DirectFileAccessOnPrivateComputersEnabled,AllowOfflineOn
  
   $OWAPolicyObj = foreach ($policy in $OWAPolicies) {
  
   [PSCustomObject]@{
    'OWA Policy Identity'           = $policy.Identity
    'IsDefault'                     = $policy.IsDefault
    'Instant messaging'             = $policy.InstantMessagingEnabled
    'Text messaging'                = $policy.TextMessagingEnabled
    'Exchange ActiveSync'           = $policy.ActiveSyncIntegrationEnabled
    'Contacts'                      = $policy.ContactsEnabled 
    'Mobile device contact sync'    = $policy.AllowCopyContactsToDeviceAddressBook
    'LinkedInEnabled'               = $policy.LinkedInEnabled
    'All address lists'             = $policy.AllAddressListsEnabled
    'Journaling'                    = $policy.JournalEnabled
    'Notes' = $policy.NotesEnabled
    'Inbox Rules' = $policy.RulesEnabled
    'Recover deleted items' = $policy.RecoverDeletedItemsEnabled
    'Themes' = $policy.ThemeSelectionEnabled
    'Premium Client' = $policy.PremiumClientEnabled
    'Email signature' = $policy.SignaturesEnabled
    'Weather' = $policy.WeatherEnabled
    'Places' = $policy.PlacesEnabled
    'Local Events' = $policy.LocalEventsEnabled
    'Interesting calendars' = $policy.InterestingCalendarsEnabled
    'Calendar' = $policy.CalendarEnabled
    'Tasks' = $policy.TasksEnabled
    'Reminders and notifications' = $policy.RemindersAndNotificationsEnabled
    'Direct File Access' = $policy.DirectFileAccessOnPrivateComputersEnabled
    'Enable offline access' = $policy.AllowOfflineOn
  }
  
   }
  
   
  
   ##GET Mobile Device Mailbox Policies
   Write-Host "Getting Mobile Device Mailbox Policies" -ForegroundColor Green
   $MobileDevicePolicy = Get-ActiveSyncMailboxPolicy | Select-Object Identity,isDefault,AllowNonProvisionableDevices,DevicePasswordEnabled,AllowSimpleDevicePassword,AlphanumericDevicePasswordRequired,MinDevicePasswordComplexCharacters,RequireDeviceEncryption,MinDevicePasswordLength,MaxDevicePasswordFailedAttempts,MaxInactivityTimeDeviceLock,DevicePasswordExpiration,DevicePasswordHistory
  
   $MobileDevicePolicyObj = foreach ($policy in $MobileDevicePolicy) {
    [PSCustomObject]@{
      'Mobile Device Policy Identity' = $policy.Identity
      'IsDefault' = $policy.IsDefault
      'Allow mobile devices that dont fully support these policies to synchronize' = $policy.AllowNonProvisionableDevices
      'Require a password' = $policy.DevicePasswordEnabled
      'Allow Simple Passwords' = $policy.AllowSimpleDevicePassword
      'Require AlphaNumeric Password' = $policy.AlphanumericDevicePasswordRequired
      'Password must include this many character sets' = $policy.MinDevicePasswordComplexCharacters
      'Require Device Encryption ' = $policy.RequireDeviceEncryption 
      'MinDevicePasswordLength' = if($policy.MinDevicePasswordLength){$policy.MinDevicePasswordLength}else{"Not Applied"}
      'Number of sign-in failures before device is wiped' = $policy.MaxDevicePasswordFailedAttempts 
      'Require sign-in after the device has been inactive for (minutes)' = $policy.MaxInactivityTimeDeviceLock
      'Enforce password lifetime (days)' = $policy.DevicePasswordExpiration
      'Password recycle count' = $policy.DevicePasswordHistory
   }
  
  }
  
  ##GET Retention Policies
  Write-Host "Getting Retention Policies" -ForegroundColor Green
  $RetentionPolicy = Get-RetentionPolicy | Select-Object Name,RetentionPolicyTagLinks 
  ##GET Retention Policy Tags
  Write-Host "Getting Retention Policy Tags" -ForegroundColor Green
  $RetentionPolicyTags = Get-RetentionPolicyTag | Select-Object Name,Type,RetentionEnabled,AgeLimitForRetention,RetentionAction 
  
  ##Get Journal Rules
  Write-Host "Getting Journal Rules" -ForegroundColor Green
  $JournalRules= Get-JournalRule  | Select-Object Name,Recipient,JournalEmailAddress,Scope,Enabled
  
  ###Get Antiphish Policies
  
  Write-Host "Getting Antiphish Policies" -ForegroundColor Green
  $Antiphish = Get-AntiPhishPolicy | Select-object -Property * -ExcludeProperty RunspaceId,ExchangeVersion,DistinguishedName,ObjectCategory,ObjectClass,WhenChangedUTC,WhenCreatedUTC,ExchangeObjectId,OrganizationalUnitRoot,OrganizationId,Guid,OriginatingServer,ObjectState
  
  $AntiphishObj = foreach ($policy in $Antiphish) {
    [PSCustomObject]@{
      name                                          = $policy.name
      Enabled                                       = $policy.enabled
      isDefault                                     = $policy.isDefault
      WhenCreated                                   = $policy.WhenCreated
      WhenChanged                                   = $policy.WhenChanged
      ImpersonationProtectionState                  = $policy.ImpersonationProtectionState
      EnableTargetedUserProtection                  = $policy.EnableTargetedUserProtection
      EnableMailboxIntelligenceProtection           = $policy.EnableMailboxIntelligenceProtection
      EnableTargetedDomainsProtection               = $policy.EnableTargetedDomainsProtection  
      EnableOrganizationDomainsProtection           = $policy.EnableOrganizationDomainsProtection
      EnableMailboxIntelligence                     = $policy.EnableMailboxIntelligence
      EnableFirstContactSafetyTips                  = $policy.EnableFirstContactSafetyTips
      EnableSimilarUsersSafetyTips                  = $policy.EnableSimilarUsersSafetyTips
      EnableSimilarDomainsSafetyTips                = $policy.EnableSimilarDomainsSafetyTips
      EnableUnusualCharactersSafetyTips             = $policy.EnableUnusualCharactersSafetyTips 
      TargetedUserProtectionAction                  = $policy.TargetedUserProtectionAction
      TargetedUserQuarantineTag                     = $policy.TargetedUserQuarantineTag  
      MailboxIntelligenceProtectionAction           = $policy.MailboxIntelligenceProtectionAction
      MailboxIntelligenceQuarantineTag              = $policy.MailboxIntelligenceQuarantineTag
      TargetedDomainProtectionAction                = $policy.TargetedDomainProtectionAction
      TargetedDomainQuarantineTag                   = $policy.TargetedDomainQuarantineTag 
      AuthenticationFailAction                      = $policy.AuthenticationFailAction
      SpoofQuarantineTag                            = $policy.SpoofQuarantineTag 
      EnableSpoofIntelligence                       = $policy.EnableSpoofIntelligence
      EnableViaTag                                  = $policy.EnableViaTag 
      EnableUnauthenticatedSender                   = $policy.EnableUnauthenticatedSender
      EnableSuspiciousSafetyTip                     = $policy.EnableSuspiciousSafetyTip
      PhishThresholdLevel                           = $policy.PhishThresholdLevel
      TargetedUsersToProtect                        = $policy.TargetedUsersToProtect -join(" ")
      TargetedUserActionRecipients                  = $policy.TargetedUserActionRecipients -join(" ")
      MailboxIntelligenceProtectionActionRecipients = $policy.MailboxIntelligenceProtectionActionRecipients -join(" ")
      TargetedDomainsToProtect                      = $policy.TargetedDomainsToProtect -join(" ")
      TargetedDomainActionRecipients                = $policy.TargetedDomainActionRecipients -join(" ")
      ExcludedDomains                               = $policy.ExcludedDomains -join(" ")
      ExcludedSenders                               = $policy.ExcludedSenders -join(" ")
    
    }
  }
  
  ##GET OUTBOUND SPAM
  Write-Host "Getting Outbound Spam Policy" -ForegroundColor Green
  $OutboundSpam = Get-HostedOutboundSpamFilterPolicy | Select-Object Name,BccSuspiciousOutboundMail,NotifyOutboundSpam,RecipientLimitExternalPerHour,RecipientLimitInternalPerHour,RecipientLimitPerDay,ActionWhenThresholdReached,AutoForwardingMode
  
  ##GET ANTISPAM
  Write-Host "Getting Antispam Policy" -ForegroundColor Green
  $AntiSpam = Get-HostedContentFilterPolicy  | Select-Object -Property * -ExcludeProperty OrganizationalUnitRoot
  
  $AntiSpamObj = foreach ($policy in $AntiSpam) {
    
  [PSCustomObject]@{
      Name                                     = $policy.Name
      IsDefault                                = $policy.IsDefault 
      WhenChanged                              = $policy.WhenChanged
      WhenCreated                              = $policy.WhenCreated
      AdminDisplayName                         = $policy.AdminDisplayName 
      AddXHeaderValue                          = $policy.AddXHeaderValue 
      ModifySubjectValue                       = $policy.ModifySubjectValue 
      RedirectToRecipients                     = $policy.RedirectToRecipients -join(" ")
      TestModeBccToRecipients                  = $policy.TestModeBccToRecipients -join(" ")
      FalsePositiveAdditionalRecipients        = $policy.FalsePositiveAdditionalRecipients -join(" ")
      QuarantineRetentionPeriod                = $policy.QuarantineRetentionPeriod  
      EndUserSpamNotificationFrequency         = $policy.EndUserSpamNotificationFrequency 
      TestModeAction                           = $policy.TestModeAction 
      IncreaseScoreWithImageLinks              = $policy.IncreaseScoreWithImageLinks
      IncreaseScoreWithNumericIps              = $policy.IncreaseScoreWithNumericIps
      IncreaseScoreWithRedirectToOtherPort     = $policy.IncreaseScoreWithRedirectToOtherPort  
      IncreaseScoreWithBizOrInfoUrls           = $policy.IncreaseScoreWithBizOrInfoUrls 
      MarkAsSpamEmptyMessages                  = $policy.MarkAsSpamEmptyMessages  
      MarkAsSpamJavaScriptInHtml               = $policy.MarkAsSpamJavaScriptInHtml
      MarkAsSpamFramesInHtml                   = $policy.MarkAsSpamFramesInHtml  
      MarkAsSpamObjectTagsInHtml               = $policy.MarkAsSpamObjectTagsInHtml
      MarkAsSpamEmbedTagsInHtml                = $policy.MarkAsSpamEmbedTagsInHtml 
      MarkAsSpamFormTagsInHtml                 = $policy.MarkAsSpamFormTagsInHtml 
      MarkAsSpamWebBugsInHtml                  = $policy.MarkAsSpamWebBugsInHtml  
      MarkAsSpamSensitiveWordList              = $policy.MarkAsSpamSensitiveWordList
      MarkAsSpamSpfRecordHardFail              = $policy.MarkAsSpamSpfRecordHardFail
      MarkAsSpamFromAddressAuthFail            = $policy.MarkAsSpamFromAddressAuthFail  
      MarkAsSpamBulkMail                       = $policy.MarkAsSpamBulkMail
      MarkAsSpamNdrBackscatter                 = $policy.MarkAsSpamNdrBackscatter 
      LanguageBlockList                        = $policy.LanguageBlockList -join(" ")
      RegionBlockList                          = $policy.RegionBlockList -join(" ")
      HighConfidenceSpamAction                 = $policy.HighConfidenceSpamAction
      SpamAction                               = $policy.SpamAction  
      EnableEndUserSpamNotifications           = $policy.EnableEndUserSpamNotifications 
      DownloadLink                             = $policy.DownloadLink
      EnableRegionBlockList                    = $policy.EnableRegionBlockList
      EnableLanguageBlockList                  = $policy.EnableLanguageBlockList
      EndUserSpamNotificationCustomFromAddress = $policy.EndUserSpamNotificationCustomFromAddress
      EndUserSpamNotificationCustomFromName    = $policy.EndUserSpamNotificationCustomFromName
      EndUserSpamNotificationCustomSubject     = $policy.EndUserSpamNotificationCustomSubject
      EndUserSpamNotificationLanguage          = $policy.EndUserSpamNotificationLanguage
      EndUserSpamNotificationLimit             = $policy.EndUserSpamNotificationLimit 
      BulkThreshold                            = $policy.BulkThreshold
      AllowedSenders                           = $policy.AllowedSenders -join(" ")
      AllowedSenderDomains                     = $policy.AllowedSenderDomains -join(" ")
      BlockedSenders                           = $policy.BlockedSenders -join(" ")
      BlockedSenderDomains                     = $policy.BlockedSenderDomains -join(" ") 
      ZapEnabled                               = $policy.ZapEnabled 
      InlineSafetyTipsEnabled                  = $policy.InlineSafetyTipsEnabled 
      BulkSpamAction                           = $policy.BulkSpamAction
      PhishSpamAction                          = $policy.PhishSpamAction 
      SpamZapEnabled                           = $policy.SpamZapEnabled 
      PhishZapEnabled                          = $policy.PhishZapEnabled  
      ApplyPhishActionToIntraOrg               = $policy.ApplyPhishActionToIntraOrg
      HighConfidencePhishAction                = $policy.HighConfidencePhishAction 
      RecommendedPolicyType                    = $policy.RecommendedPolicyType  
      SpamQuarantineTag                        = $policy.SpamQuarantineTag
      HighConfidenceSpamQuarantineTag          = $policy.HighConfidenceSpamQuarantineTag  
      PhishQuarantineTag                       = $policy.PhishQuarantineTag 
      HighConfidencePhishQuarantineTag         = $policy.HighConfidencePhishQuarantineTag 
      BulkQuarantineTag                        = $policy.BulkQuarantineTag 
    }
  }
  
  ##GET Antimalware Policy
  Write-Host "Getting Antimalware Policy" -ForegroundColor Green
  $Malware = ""
  $Malware = Get-MalwareFilterPolicy | Select-Object -Property * 
  
  $malwareObj = foreach ($policy in $Malware) {
    [PSCustomObject]@{
      Name                                   = $policy.Name
      IsDefault                              = $policy.IsDefault
      WhenChanged                            = $policy.WhenChanged 
      WhenCreated                            = $policy.WhenCreated  
      CustomAlertText                        = $policy.CustomAlertText
      AdminDisplayName                       = $policy.AdminDisplayName
      CustomInternalSubject                  = $policy.CustomInternalSubject 
      CustomInternalBody                     = $policy.CustomInternalBody
      CustomExternalSubject                  = $policy.CustomExternalSubject
      CustomExternalBody                     = $policy.CustomExternalBody 
      CustomFromName                         = $policy.CustomFromName
      CustomFromAddress                      = $policy.CustomFromAddress 
      InternalSenderAdminAddress             = $policy.InternalSenderAdminAddress
      ExternalSenderAdminAddress             = $policy.ExternalSenderAdminAddress
      BypassInboundMessages                  = $policy.BypassInboundMessages
      BypassOutboundMessages                 = $policy.BypassOutboundMessages  
      Action                                 = $policy.Action
      CustomNotifications                    = $policy.CustomNotifications 
      EnableInternalSenderNotifications      = $policy.EnableInternalSenderNotifications
      EnableExternalSenderNotifications      = $policy.EnableExternalSenderNotifications 
      EnableInternalSenderAdminNotifications = $policy.EnableInternalSenderAdminNotifications
      EnableExternalSenderAdminNotifications = $policy.EnableExternalSenderAdminNotifications
      EnableFileFilter                       = $policy.EnableFileFilter
      FileTypes                              = $policy.FileTypes -join(" ")
      QuarantineTag                          = $policy.QuarantineTag
      ZapEnabled                             = $policy.ZapEnabled  
      RecommendedPolicyType                  = $policy.RecommendedPolicyType  
    }
  }
  
  ##GET Safe Attachment Policies
  Write-Host "Getting Safe Attachment Policies" -ForegroundColor Green
  $SafeAttachment = Get-SafeAttachmentPolicy | Select-Object -Property * 
  $SafeAttachmentRule = Get-SafeAttachmentRule | Select-Object -Property *
  
  $SafeAttachmentObj = foreach ($policy in $SafeAttachment) {
    [PSCustomObject]@{
      Name                       = $policy.Name
      IsDefault                  = $policy.IsDefault
      WhenChanged                = $policy.WhenChanged
      WhenCreated                = $policy.WhenCreated
      SentTo                     = ($SafeAttachmentRule | ? {$_.Name -eq $policy.Name} ).SentTo
      SentToMemberOf             = ($SafeAttachmentRule | ? {$_.Name -eq $policy.Name} ).SentToMemberOf 
      RecipientDomainIs          = ($SafeAttachmentRule | ? {$_.Name -eq $policy.Name} ).RecipientDomainIs -join(' ')
      ExceptIfSentTo             = ($SafeAttachmentRule | ? {$_.Name -eq $policy.Name} ).ExceptIfSentTo -join(' ')
      ExceptIfSentToMemberOf     = ($SafeAttachmentRule | ? {$_.Name -eq $policy.Name} ).ExceptIfSentToMemberOf
      ExceptIfRecipientDomainIs  = ($SafeAttachmentRule | ? {$_.Name -eq $policy.Name} ).ExceptIfRecipientDomainIs
      RedirectAddress            = $policy.RedirectAddress 
      Redirect                   = $policy.Redirec
      Action                     = $policy.Action
      ScanTimeout                = $policy.ScanTimeout
      ConfidenceLevelThreshold   = $policy.ConfidenceLevelThreshold 
      OperationMode              = $policy.OperationMode
      Enable                     = $policy.Enable  
      ActionOnError              = $policy.ActionOnError  
      RecommendedPolicyType      = $policy.RecommendedPolicyType
      IsBuiltInProtection        = $policy.IsBuiltInProtection
      AdminDisplayName           = $policy.AdminDisplayName
      QuarantineTag              = $policy.QuarantineTag
      EnableOrganizationBranding = $policy.EnableOrganizationBranding
    }
  }
  
  ##GET Safe Link Policies
  Write-Host "Getting Safe Link Policies" -ForegroundColor Green
  $SafeLink = Get-SafeLinksPolicy | Select-Object -Property * 
  $SafeLinkRule = Get-SafeLinksRule | Select-Object -Property *
  
  $SafeLinkObj = foreach ($policy in $SafeLink) {
    [PSCustomObject]@{
      Name                          = $policy.Name
      IsEnabled                     = $policy.IsEnabled  
      IsDefault                     = $policy.IsDefault  
      WhenChanged                   = $policy.WhenChanged
      WhenCreated                   = $policy.WhenCreated
      SentTo                        = ($SafeLinkRule | ? {$_.Name -eq $policy.Name} ).SentTo
      SentToMemberOf                = ($SafeLinkRule | ? {$_.Name -eq $policy.Name} ).SentToMemberOf 
      RecipientDomainIs             = ($SafeLinkRule | ? {$_.Name -eq $policy.Name} ).RecipientDomainIs -join(' ')
      ExceptIfSentTo                = ($SafeLinkRule | ? {$_.Name -eq $policy.Name} ).ExceptIfSentTo -join(' ')
      ExceptIfSentToMemberOf        = ($SafeLinkRule | ? {$_.Name -eq $policy.Name} ).ExceptIfSentToMemberOf
      ExceptIfRecipientDomainIs     = ($SafeLinkRule | ? {$_.Name -eq $policy.Name} ).ExceptIfRecipientDomainIs
      TrackClicks                   = $policy.TrackClicks 
      DoNotTrackUserClicks          = $policy.DoNotTrackUserClicks  
      AllowClickThrough             = $policy.AllowClickThrough
      DoNotAllowClickThrough        = $policy.DoNotAllowClickThrough 
      ScanUrls                      = $policy.ScanUrls 
      EnableForInternalSenders      = $policy.EnableForInternalSenders
      DeliverMessageAfterScan       = $policy.DeliverMessageAfterScan
      WhiteListedUrls               = $policy.WhiteListedUrls
      ExcludedUrls                  = $policy.ExcludedUrls -join(" ")
      DoNotRewriteUrls              = $policy.DoNotRewriteUrls -join(" ")
      AdminDisplayName              = $policy.AdminDisplayName
      EnableSafeLinksForTeams       = $policy.EnableSafeLinksForTeams 
      DisableUrlRewrite             = $policy.DisableUrlRewrite
      CustomNotificationText        = $policy.CustomNotificationText 
      EnableOrganizationBranding    = $policy.EnableOrganizationBranding
      RecommendedPolicyType         = $policy.RecommendedPolicyType
      IsBuiltInProtection           = $policy.IsBuiltInProtection
    }
  }
  
  ##GET DKIM Configuration
  Write-Host "Getting DKIM Configuration" -ForegroundColor Green
  $DKIM = Get-DkimSigningConfig | Select-Object Domain,Enabled
  
  ##GET ACCEPTED DOMAINS
  Write-Host "Getting Accepted Domains" -ForegroundColor Green
  $AcceptedDomains = Get-AcceptedDomain | Select-Object DomainName,DomainType,Default 
  
   ##Get Legacy Auth Settings if Available
   Write-Host "Getting Legacy Auth Settings" -ForegroundColor Green
   $LegacyAuthSettings = Get-AuthenticationPolicy | Select-Object AllowBasicAuthActiveSync, AllowBasicAuthAutodiscover,AllowBasicAuthImap,AllowBasicAuthMapi,AllowBasicAuthPop,AllowBasicAuthSmtp,AllowBasicAuthPowershell
   Remove-PSSession $session
}
$FlexAssetBody = 
@{
    type       = "flexible-assets"
    attributes = @{
        traits = @{
            "customer-name"                 = $customer.Name
            "legacy-auth-settings"          = ($LegacyAuthSettings| convertto-html -Fragment  | out-string)
            "mail-transport-rules"          = ($TransportRule | convertto-html -Fragment | out-string)
            "owa-policies"                  = ($OWAPolicyObj | convertto-html -Fragment  | out-string)
            "accepted-domains"              = ($AcceptedDomains | convertto-html -Fragment  | out-string)
            "journal-rules"                 = ($JournalRules | convertto-html -Fragment  | out-string)
            "mobile-device-policy"          = ($MobileDevicePolicyObj | convertto-html -Fragment  | out-string)
            "retention-policy"              = ($RetentionPolicy | convertto-html -Fragment  | out-string)
            "retention-policy-tags"         = ($RetentionPolicyTags | convertto-html -Fragment  | out-string)
            "antiphishing-polciies"         = ($AntiphishObj | convertto-html -Fragment  | out-string)
            "outbound-spam-policy"          = ($OutboundSpam | convertto-html -Fragment  | out-string)
            "antispam-policies"             = ($AntiSpamObj | convertto-html -Fragment  | out-string)
            "antimalware-policies"          = ($malwareObj | convertto-html -Fragment  | out-string)
            "safe-attachment-policies"      = ($SafeAttachmentObj | convertto-html -Fragment  | out-string)
            "safe-links-policies"           = ($SafeLinkObj | convertto-html -Fragment  | out-string)
            "dkim"                          = ($DKIM | convertto-html -Fragment  | out-string)
                                 
        }
    }
}

 $ExistingFlexAsset = (Get-ITGlueFlexibleAssets -filter_flexible_asset_type_id $($filterID.id) -filter_organization_id $orgID).data | Where-Object { $_.attributes.traits.'customer-name' -eq $customer.name}
#If the Asset does not exist, we edit the body to be in the form of a new asset, if not, we just update.
if (!$ExistingFlexAsset) {
    $FlexAssetBody.attributes.add('organization-id', $orgID)
    $FlexAssetBody.attributes.add('flexible-asset-type-id', $($filterID.ID))
    write-host "Creating Exchange seetings for $($customer.name) into IT-Glue" -ForegroundColor Green
    New-ITGlueFlexibleAssets -data $FlexAssetBody
}
else {
    write-host "Updating Exchange Settings  for $($customer.name) into IT-Glue"  -ForegroundColor Yellow
    $ExistingFlexAsset = $ExistingFlexAsset | select-object -last 1
    Set-ITGlueFlexibleAssets -id $ExistingFlexAsset.id -data $FlexAssetBody
}


}
}