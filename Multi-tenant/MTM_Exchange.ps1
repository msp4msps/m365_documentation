<#
  .SYNOPSIS
  This function is used to add an MDM application using the Graph API REST interface
  .DESCRIPTION
  The function connects to the Graph API Interface and adds an MDM application from the itunes store
  .EXAMPLE
  Add-MDMApplication -JSON $JSON1
  Adds an application into Intune
  .NOTES
  NAME: Add-MDMApplication
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
        [string]$upn
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
$SafeAttachmentObj = ""
$DKIM = ""


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


##GET DOMAIN 
$customerDomain = (Get-MsolDomain -TenantId $customer.TenantID).name[1]

#Define CSV Path 
$path = echo ([Environment]::GetFolderPath("Desktop")+"\Microsoft_${customerDomain}_OrgReports")
New-Item -ItemType Directory -Force -Path $path
##Legacy Auth CSV Path
if($LegacyAuthSettings){
    $LegacyAuthSettingsReport = echo ([Environment]::GetFolderPath("Desktop")+"\Microsoft_${customerDomain}_OrgReports\LegacyAuthSettings.csv")
    $LegacyAuthSettings | Export-CSV -Path $LegacyAuthSettingsReport -NoTypeInformation -Append
}
##Transport Rules CSV Path
if($TransportRule){
$TransportRuleReport = echo ([Environment]::GetFolderPath("Desktop")+"\Microsoft_${customerDomain}_OrgReports\TransportRule.csv")
$TransportRule | Export-CSV -Path $TransportRuleReport -NoTypeInformation -Append
}
##OWA Policy CSV Path
if($OWAPolicyObj){
$OWAPolicyReport = echo ([Environment]::GetFolderPath("Desktop")+"\Microsoft_${customerDomain}_OrgReports\OWAPolicy.csv")
$OWAPolicyObj | Export-CSV -Path $OWAPolicyReport -NoTypeInformation -Append
}
##Accepted Domains CSV Path
if($AcceptedDomains){
$AcceptedDomainsReport = echo ([Environment]::GetFolderPath("Desktop")+"\Microsoft_${customerDomain}_OrgReports\AcceptedDomains.csv")
$AcceptedDomains | Export-CSV -Path $AcceptedDomainsReport -NoTypeInformation -Append
}
##Mobile Device Policy CSV Path
if($MobileDevicePolicyObj){
$MobileDevicePolicyReport = echo ([Environment]::GetFolderPath("Desktop")+"\Microsoft_${customerDomain}_OrgReports\MobileDevicePolicy.csv")
$MobileDevicePolicyObj | Export-CSV -Path $MobileDevicePolicyReport -NoTypeInformation -Append
}
##Retention Policy CSV Path
if($RetentionPolicy){
$RetentionPolicyReport = echo ([Environment]::GetFolderPath("Desktop")+"\Microsoft_${customerDomain}_OrgReports\RetentionPolicy.csv")
$RetentionPolicy | Export-CSV -Path $RetentionPolicyReport -NoTypeInformation -Append
}
##Retention Tags CSV Path
if($RetentionPolicyTags){
$RetentionTagReport = echo ([Environment]::GetFolderPath("Desktop")+"\Microsoft_${customerDomain}_OrgReports\RetentionTag.csv")
$RetentionPolicyTags | Export-CSV -Path $RetentionTagReport -NoTypeInformation -Append
}
##Journal Rules CSV Path
if($JournalRules){
$JournalRulesReport = echo ([Environment]::GetFolderPath("Desktop")+"\Microsoft_${customerDomain}_OrgReports\JournalRules.csv")
$JournalRules | Export-CSV -Path $JournalRulesReport -NoTypeInformation -Append
}
##Antiphish CSV Path
if($AntiphishObj){
$AntiphishReport = echo ([Environment]::GetFolderPath("Desktop")+"\Microsoft_${customerDomain}_OrgReports\Antiphish.csv")
$AntiphishObj  | Export-CSV -Path $AntiphishReport -NoTypeInformation -Append
}
##OutboundSpam CSV Path
if($OutboundSpam){
$OutboundSpamReport = echo ([Environment]::GetFolderPath("Desktop")+"\Microsoft_${customerDomain}_OrgReports\OutboundSpam.csv")
$OutboundSpam | Export-CSV -Path $OutboundSpamReport -NoTypeInformation -Append
}
##AntiSpam CSV Path
if($AntiSpamObj){
$AntiSpamReport = echo ([Environment]::GetFolderPath("Desktop")+"\Microsoft_${customerDomain}_OrgReports\AntiSpam.csv")
$AntiSpamObj | Export-CSV -Path $AntiSpamReport -NoTypeInformation -Append
}
##AntiMalwareCSV Path
if($malwareObj){
$AntimalwareReport = echo ([Environment]::GetFolderPath("Desktop")+"\Microsoft_${customerDomain}_OrgReports\AntiMalware.csv")
$malwareObj | Export-CSV -Path $AntimalwareReport -NoTypeInformation -Append
}
##Safe Attachment CSV Path
if($SafeAttachmentObj){
$SafeAttachReport = echo ([Environment]::GetFolderPath("Desktop")+"\Microsoft_${customerDomain}_OrgReports\SafeAttachment.csv")
$SafeAttachmentObj | Export-CSV -Path $SafeAttachReport -NoTypeInformation -Append
}
##Safe Link CSV Path
if($SafeAttachmentObj){
$SafeLinkReport = echo ([Environment]::GetFolderPath("Desktop")+"\Microsoft_${customerDomain}_OrgReports\SafeLink.csv")
$SafeLinkObj | Export-CSV -Path $SafeLinkReport  -NoTypeInformation -Append
}
##DKIM CSV Path
if($DKIM){
$DKIMReport = echo ([Environment]::GetFolderPath("Desktop")+"\Microsoft_${customerDomain}_OrgReports\DKIM.csv")
$DKIM | Export-CSV -Path $DKIMReport  -NoTypeInformation -Append
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
$outputfilename = "$path\$(${customerDomain})_OrgSettings.xlsx"
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
}