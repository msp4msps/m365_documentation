<#
  .SYNOPSIS
  This script is used to garner organization information such as policies and settings from a single tenant and output that information to a CSV file
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
$ExchangeRefreshToken = $ExchangeRefreshToken
$upn = $upn
$secPas = $ApplicationSecret| ConvertTo-SecureString -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($ApplicationId, $secPas)



###Connect to your Own Partner Center to get a list of customers/tenantIDs #########
$aadGraphToken = New-PartnerAccessToken -ApplicationId $ApplicationId -Credential $credential -RefreshToken $refreshToken -Scopes 'https://graph.windows.net/.default' -ServicePrincipal -Tenant $tenantID
$graphToken = New-PartnerAccessToken -ApplicationId $ApplicationId -Credential $credential -RefreshToken $refreshToken -Scopes 'https://graph.microsoft.com/.default' -ServicePrincipal -Tenant $tenantID


Connect-MsolService -AdGraphAccessToken $aadGraphToken.AccessToken -MsGraphAccessToken $graphToken.AccessToken


##GET DOMAIN 
$customerDomain = (Get-MsolDomain -TenantId $customerTenantID).name[1]



## Connect to Exchange
Write-Host "Connecting to Exchange" -ForegroundColor Green
$token = New-PartnerAccessToken -ApplicationId 'a0c73c16-a7e3-4564-9a95-2bdf47383716'-RefreshToken $ExchangeRefreshToken -Scopes 'https://outlook.office365.com/.default' -Tenant $customerTenantID -ErrorAction SilentlyContinue
    $tokenValue = ConvertTo-SecureString "Bearer $($token.AccessToken)" -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential($upn, $tokenValue)
    $InitialDomain = Get-MsolDomain -TenantId $customerTenantID | Where-Object {$_.IsInitial -eq $true}
    $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "https://ps.outlook.com/powershell-liveid?DelegatedOrg=$($InitialDomain)&BasicAuthToOAuthConversion=true" -Credential $credential -Authentication Basic -AllowRedirection -ErrorAction SilentlyContinue
    Import-PSSession $session  -AllowClobber -ErrorAction SilentlyContinue


 
    $CustomerToken = New-PartnerAccessToken -ApplicationId $ApplicationId -Credential $credential -RefreshToken $refreshToken -Scopes 'https://graph.microsoft.com/.default' -Tenant $customerTenantID
    $headers = @{ "Authorization" = "Bearer $($CustomerToken.AccessToken)" }

try{

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

}catch{"Could not connect to exchange"}

if($session){Remove-PSSession $session}


###Azure AD Settings####
Write-Host "Getting AzureAD Settings" -ForegroundColor Green
$AzureADSettings = Get-MsolCompanyInformation | select-object @{ Name = 'CompanyName'; Expression = { $_.'DisplayName' } },
@{ Name = 'SSPR Enabled'; Expression = { $_.'SelfServePasswordResetEnabled' } },
@{ Name = 'Can Users Register Applications'; Expression = { $_.'UsersPermissionToCreateLOBAppsEnabled' } },
@{ Name = 'Can User Consent for Applications'; Expression = { $_.'UsersPermissionToUserConsentToAppEnabled' } }


 ##Get Legacy Auth Sign-Ins
 Write-Host "Getting Legacy Auth Sign ins" -ForegroundColor Green
 ##Set 30 day period for audit log records
 $currentTime = Get-Date -Format "yyyy-MM-ddTHH:MM:ss"
 $ts = (Get-Date).AddDays(-30)
 $endTime = $ts.ToString("yyyy-MM-ddTHH:MM:ss")
 ##Create Filter for basic auth sign-ins
 $filters= "createdDateTime ge $($endTime)Z and createdDateTime lt $($currentTime)Z and (clientAppUsed eq 'AutoDiscover' or clientAppUsed eq 'Exchange ActiveSync' or clientAppUsed eq 'Exchange Online PowerShell' or clientAppUsed eq 'Exchange Web Services' or clientAppUsed eq 'IMAP4' or clientAppUsed eq 'MAPI Over HTTP' or clientAppUsed eq 'Offline Address Book' or clientAppUsed eq 'Outlook Anywhere (RPC over HTTP)' or clientAppUsed eq 'Other clients' or clientAppUsed eq 'POP3' or clientAppUsed eq 'Reporting Web Services' or clientAppUsed eq 'Authenticated SMTP' or clientAppUsed eq 'Outlook Service')"
 $uri = "https://graph.microsoft.com/beta/auditLogs/signIns?api-version=beta&filter=$($filters)"
 try{
 ##Try to make call to test if tenant has P1 licensing
 $signIns = (Invoke-RestMethod -Uri $uri -Headers $Headers -Method Get -ContentType "application/json").value | Select-Object userDisplayName, clientAppUsed
 }catch{"This client does not have a Azure AD P1 subscription or the app registration does not have the necessary permissions"
 write-host $_}
 #Remove duplicate records
 $getUnique = $signIns | Sort-Object -Unique -Property clientAppUsed
 if($getUnique){
 forEach($object in $getUnique){
  Write-Host "Basic Auth discovered: $($object.clientAppUsed)" -ForegroundColor Yellow
  $user = $object.userDisplayName
  $basicAuth = $object.clientAppUsed
  $LegacyAuthSignIn = 
       [PSCustomObject]@{
         'Basic Auth Used' = $basicAuth
         'UserDisplayName' = $user  
       }}
 }



##Conditional Access
Write-Host "Getting Conditional Access Policies" -ForegroundColor Green
try{

  function Get-LocationNameFromId {
    [CmdletBinding()]
    param (
        [Parameter()]
        $ID,
        
        [Parameter(Mandatory = $true)]
        $Locations
    )
    if ($id -eq 'All') {
        return 'All'
    }
    $DisplayName = $Locations | ? { $_.id -eq $ID } | Select -ExpandProperty DisplayName
    if ([string]::IsNullOrEmpty($displayName)) {
        return ""
    }
    else {
        return $DisplayName
    }
}

function Get-RoleNameFromId {
    [CmdletBinding()]
    param (
        [Parameter()]
        $ID,
        
        [Parameter(Mandatory = $true)]
        $RoleDefinitions
    )
    if ($id -eq 'All') {
        return 'All'
    }
    $DisplayName = $RoleDefinitions | ? { $_.id -eq $ID } | Select -ExpandProperty DisplayName
    if ([string]::IsNullOrEmpty($displayName)) {
        return ""
    }
    else {
        return $DisplayName
    }
}

function Get-UserNameFromId {
    [CmdletBinding()]
    param (
        [Parameter()]
        $ID,
        
        [Parameter(Mandatory = $true)]
        $Users
    )
    if ($id -eq 'All') {
        return 'All'
    }
    $DisplayName = $Users | ? { $_.id -eq $ID } | Select -ExpandProperty DisplayName
    if ([string]::IsNullOrEmpty($displayName)) {
        return ""
    }
    else {
        return $DisplayName
    }
}

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

function Get-ApplicationNameFromId {
    [CmdletBinding()]
    param (
        [Parameter()]
        $ID,
        
        [Parameter(Mandatory = $true)]
        $Applications
    )
    if ($id -eq 'All') {
        return 'All'
    }
    switch ($id) {
        00000004-0000-0ff1-ce00-000000000000 { $return = 'Microsoft.Lync' }
        00000006-0000-0ff1-ce00-000000000000 { $return = 'Microsoft.Office365Portal' }
        00000003-0000-0ff1-ce00-000000000000 { $return = 'Microsoft.SharePoint ' }
        00000005-0000-0000-c000-000000000000 { $return = 'Microsoft.Azure.Workflow' }
        00000009-0000-0000-c000-000000000000 { $return = 'Microsoft.Azure.AnalysisServices' }
        00000002-0000-0ff1-ce00-000000000000 { $return = 'Microsoft.Exchange' }
        00000007-0000-0ff1-ce00-000000000000 { $return = 'Microsoft.ExchangeOnlineProtection' }
        00000002-0000-0000-c000-000000000000 { $return = 'Microsoft.Azure.ActiveDirectory' }
        8fca0a66-c008-4564-a876-ab3ae0fd5cff { $return = 'Microsoft.SMIT' }
        0000000b-0000-0000-c000-000000000000 { $return = 'Microsoft.SellerDashboard' }
        0000000f-0000-0000-c000-000000000000 { $return = 'Microsoft.Azure.GraphExplorer' }
        0000000c-0000-0000-c000-000000000000 { $return = 'Microsoft App Access Panel' }
        00000013-0000-0000-c000-000000000000 { $return = 'Microsoft.Azure.Portal' }
        00000010-0000-0000-c000-000000000000 { $return = 'Microsoft.Azure.GraphStore' }
        93ee9413-cf4c-4d4e-814b-a91ff20a01bd { $return = 'Workflow' }
        aa9ecb1e-fd53-4aaa-a8fe-7a54de2c1334 { $return = 'Microsoft.Office365.Configure' }
        797f4846-ba00-4fd7-ba43-dac1f8f63013 { $return = 'Windows Azure Service Management API' }
        00000005-0000-0ff1-ce00-000000000000 { $return = 'Microsoft.YammerEnterprise' }
        601d4e27-7bb3-4dee-8199-90d47d527e1c { $return = 'Microsoft.Office365.ChangeManagement' }
        6f82282e-0070-4e78-bc23-e6320c5fa7de { $return = 'Microsoft.DiscoveryService' }
        0f698dd4-f011-4d23-a33e-b36416dcb1e6 { $return = 'Microsoft.OfficeClientService' }
        67e3df25-268a-4324-a550-0de1c7f97287 { $return = 'Microsoft.OfficeWebAppsService' }
        ab27a73e-a3ba-4e43-8360-8bcc717114d8 { $return = 'Microsoft.OfficeModernCalendar' }
        aedca418-a84d-430d-ab84-0b1ef06f318f { $return = 'Workflow' }
        595d87a1-277b-4c0a-aa7f-44f8a068eafc { $return = 'Microsoft.SupportTicketSubmission' }
        e3583ad2-c781-4224-9b91-ad15a8179ba0 { $return = 'Microsoft.ExtensibleRealUserMonitoring' }
        b645896d-566e-447e-8f7f-e2e663b5d182 { $return = 'OpsDashSharePointApp' }
        48229a4a-9f1d-413a-8b96-4c02462c0360 { $return = 'OpsDashSharePointApp' }
        48717084-a59c-4306-9dc4-3f618dbecdf9 { $return = '"Napa" Office 365 Development Tools' }
        c859ff33-eb41-4ba6-8093-a2c5153bbd7c { $return = 'Workflow' }
        67cad61c-3411-48d7-ab73-561c64f11ed6 { $return = 'Workflow' }
        914ed757-9257-4200-b68e-a2bed2f12c5a { $return = 'RbacBackfill' }
        499b84ac-1321-427f-aa17-267ca6975798 { $return = 'Microsoft.VisualStudio.Online' }
        b2590339-0887-4e94-93aa-13357eb510d7 { $return = 'Workflow' }
        0000001b-0000-0000-c000-000000000000 { $return = 'Microsoft Power BI Information Service' }
        89f80565-bfac-4c01-9535-9f0eba332ffe { $return = 'Power BI' }
        433895fb-4ec7-45c3-a53c-c44d10f80d5b { $return = 'Compromised Account Service' }
        d7c17728-4f1e-4a1e-86cf-7e0adf3fe903 { $return = 'Workflow' }
        17ef6d31-381f-4783-b186-7b440a3c85c1 { $return = 'Workflow' }
        00000012-0000-0000-c000-000000000000 { $return = 'Microsoft.Azure.RMS' }
        81ce94d4-9422-4c0d-a4b9-3250659366ce { $return = 'Workflow' }
        8d3a7d3c-c034-4f19-a2ef-8412952a9671 { $return = 'MicrosoftOffice' }
        0469d4cd-df37-4d93-8a61-f8c75b809164 { $return = 'Microsoft Policy Administration Service' }
        31d3f3f5-7267-45a8-9549-affb00110054 { $return = 'Windows Azure RemoteApp Service' }
        4e004241-32db-46c2-a86f-aaaba29bea9c { $return = 'Workflow' }
        748d098e-7a3b-436d-8b0a-006a58b29647 { $return = 'Workflow' }
        dbf08535-1d3b-4f89-bf54-1d48dd613a61 { $return = 'Workflow' }
        ed9fe1ef-25a4-482f-9981-2b60f91e2448 { $return = 'Workflow' }
        8ad28d50-ee26-42fc-8a29-e41ea38461f2 { $return = 'Office365RESTAPIExplorer.Office365App' }
        38285dce-a13d-4107-9b04-3016b941bb3a { $return = 'BasicDataOperationsREST' }
        92bb96c8-321c-47f9-bcc5-8849490c2b07 { $return = 'BasicSelfHostedAppREST' }
        488a57a0-00e2-4817-8c8d-cf8a15a994d2 { $return = 'WindowsFormsApplication2.Office365App' }
        11c174dc-1945-4a9a-a36b-c79a0f246b9b { $return = 'AzureApplicationInsights' }
        e6acb561-0d94-4287-bd3a-3169f421b112 { $return = 'Tutum' }
        7b77b3a2-8490-49e1-8842-207cd0899af9 { $return = 'Nearpod' }
        0000000a-0000-0000-c000-000000000000 { $return = 'Microsoft.Intune' }
        93625bc8-bfe2-437a-97e0-3d0060024faa { $return = 'SelfServicePasswordReset' }
        dee7ba80-6a55-4f3b-a86c-746a9231ae49 { $return = 'MicrosoftAppPlatEMA' }
        803ee9ca-3f7f-4824-bd6e-0b99d720c35c { $return = 'Azure Media Service' }
        2d4d3d8e-2be3-4bef-9f87-7875a61c29de { $return = 'OneNote' }
        8d40666e-5abf-45f6-a5e7-b7192d6d56ed { $return = 'Workflow' }
        262044b1-e2ce-469f-a196-69ab7ada62d3 { $return = 'Backup Management Service' }
        087a2c70-c89e-463f-8dd3-e3959eabb1a9 { $return = 'Microsoft Profile Service Platform Service' }
        7cd684f4-8a78-49b0-91ec-6a35d38739ba { $return = 'Azure Logic Apps' }
        c5393580-f805-4401-95e8-94b7a6ef2fc2 { $return = 'Office 365 Management APIs' }
        96231a05-34ce-4eb4-aa6a-70759cbb5e83 { $return = 'MicrosoftAzureRedisCache' }
        b8340c3b-9267-498f-b21a-15d5547fd85e { $return = 'Hyper-V Recovery Manager' }
        abfa0a7c-a6b6-4736-8310-5855508787cd { $return = 'Microsoft.Azure.WebSites' }
        c44b4083-3bb0-49c1-b47d-974e53cbdf3c { $return = 'IbizaPortal' }
        905fcf26-4eb7-48a0-9ff0-8dcc7194b5ba { $return = 'Sway' }
        b10686fd-6ba8-49f2-a3cd-67e4d2f52ac8 { $return = 'NovoEd' }
        c606301c-f764-4e6b-aa45-7caaaea93c9a { $return = 'OfficeStore' }
        569e8598-685b-4ba2-8bff-5bced483ac46 { $return = 'Evercontact' }
        20a23a2f-8c32-4de7-8063-8c8f909602c0 { $return = 'Workflow' }
        aaf214cc-8013-4b95-975f-13203ae36039 { $return = 'Power BI Tiles' }
        d88a361a-d488-4271-a13f-a83df7dd99c2 { $return = 'IDML Graph Resolver Service and CAD' }
        dff9b531-6290-4620-afce-26826a62a4e7 { $return = 'DocuSign' }
        01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9 { $return = 'Device Registration Service' }
        3290e3f7-d3ac-4165-bcef-cf4874fc4270 { $return = 'Smartsheet' }
        a4ee6867-8640-4495-b1fd-8b26037a5bd3 { $return = 'Workflow' }
        aa0e3dd4-df02-478d-869e-fc61dd71b6e8 { $return = 'Workflow' }
        0f6edad5-48f2-4585-a609-d252b1c52770 { $return = 'AIGraphClient' }
        0c8139b5-d545-4448-8d2b-2121bb242680 { $return = 'BillingExtension' }
        475226c6-020e-4fb2-8a90-7a972cbfc1d4 { $return = 'KratosAppsService' }
        39624784-6cbe-4a60-afbe-9f46d10fdb27 { $return = 'SkypeForBusinessRemotePowershell' }
        8bdebf23-c0fe-4187-a378-717ad86f6a53 { $return = 'ResourceHealthRP' }
        c161e42e-d4df-4a3d-9b42-e7a3c31f59d4 { $return = 'MicrosoftIntuneAPI' }
        9cb77803-d937-493e-9a3b-4b49de3f5a74 { $return = 'MicrosoftIntuneServiceDiscovery' }
        ddbf3205-c6bd-46ae-8127-60eb93363864 { $return = 'Microsoft Azure Batch' }
        80ccca67-54bd-44ab-8625-4b79c4dc7775 { $return = 'ComplianceCenter' }
        0a5f63c0-b750-4f38-a71c-4fc0d58b89e2 { $return = 'Microsoft Mobile Application Management' }
        e1335bb1-2aec-4f92-8140-0e6e61ae77e5 { $return = 'CIWebService' }
        75018fbe-21fe-4a57-b63c-83252b5eaf16 { $return = 'TeamImprover - Team Organization Chart' }
        a393296b-5695-4463-97cb-9fa8638a494a { $return = 'My SharePoint Sites' }
        fe217466-5583-431c-9531-14ff7268b7b3 { $return = 'Microsoft Education' }
        5bfe8a29-054e-4348-9e7a-3981b26b125f { $return = 'Bing Places for Business' }
        eaf8a961-f56e-47eb-9ffd-936e22a554ef { $return = 'DevilFish' }
        4b4b1d56-1f03-47d9-a0a3-87d4afc913c9 { $return = 'Wunderlist' }
        00000003-0000-0000-c000-000000000000 { $return = 'Microsoft Graph' }
        60e6cd67-9c8c-4951-9b3c-23c25a2169af { $return = 'Compute Resource Provider' }
        507bc9da-c4e2-40cb-96a7-ac90df92685c { $return = 'Office365Reports' }
        09abbdfd-ed23-44ee-a2d9-a627aa1c90f3 { $return = 'ProjectWorkManagement' }
        28ec9756-deaf-48b2-84d5-a623b99af263 { $return = 'Office Personal Assistant at Work Service' }
        9e4a5442-a5c9-4f6f-b03f-5b9fcaaf24b1 { $return = 'OfficeServicesManager' }
        3138fe80-4087-4b04-80a6-8866c738028a { $return = 'SharePoint Notification Service' }
        d2a0a418-0aac-4541-82b2-b3142c89da77 { $return = 'MicrosoftAzureOperationalInsights' }
        2cf9eb86-36b5-49dc-86ae-9a63135dfa8c { $return = 'AzureTrafficManagerandDNS' }
        32613fc5-e7ac-4894-ac94-fbc39c9f3e4a { $return = 'OAuth Sandbox' }
        925eb0d0-da50-4604-a19f-bd8de9147958 { $return = 'Groupies Web Service' }
        e4ab13ed-33cb-41b4-9140-6e264582cf85 { $return = 'Azure SQL Database Backup To Azure Backup Vault' }
        ad230543-afbe-4bb4-ac4f-d94d101704f8 { $return = 'Apiary for Power BI' }
        11cd3e2e-fccb-42ad-ad00-878b93575e07 { $return = 'Automated Call Distribution' }
        de17788e-c765-4d31-aba4-fb837cfff174 { $return = 'Skype for Business Management Reporting and Analytics' }
        65d91a3d-ab74-42e6-8a2f-0add61688c74 { $return = 'Microsoft Approval Management' }
        5225545c-3ebd-400f-b668-c8d78550d776 { $return = 'Office Agent Service' }
        1cda9b54-9852-4a5a-96d4-c2ab174f9edf { $return = 'O365Account' }
        4747d38e-36c5-4bc3-979b-b0ef74df54d1 { $return = 'PushChannel' }
        b97b6bd4-a49f-4a0c-af18-af507d1da76c { $return = 'Office Shredding Service' }
        d4ebce55-015a-49b5-a083-c84d1797ae8c { $return = 'Microsoft Intune Enrollment' }
        5b20c633-9a48-4a5f-95f6-dae91879051f { $return = 'Azure Information Protection' }
        441509e5-a165-4363-8ee7-bcf0b7d26739 { $return = 'EnterpriseAgentPlatform' }
        e691bce4-6612-4025-b94c-81372a99f77e { $return = 'Boomerang' }
        8edd93e1-2103-40b4-bd70-6e34e586362d { $return = 'Windows Azure Security Resource Provider' }
        94c63fef-13a3-47bc-8074-75af8c65887a { $return = 'Office Delve' }
        e95d8bee-4725-4f59-910d-94d415da51b9 { $return = 'Skype for Business Name Dictionary Service' }
        e3c5dbcd-bb5f-4bda-b943-adc7a5bbc65e { $return = 'Workflow' }
        8602e328-9b72-4f2d-a4ae-1387d013a2b3 { $return = 'Azure API Management' }
        8b3391f4-af01-4ee8-b4ea-9871b2499735 { $return = 'O365 Secure Score' }
        c26550d6-bc82-4484-82ca-ac1c75308ca3 { $return = 'Office 365 YammerOnOls' }
        33be1cef-03fb-444b-8fd3-08ca1b4d803f { $return = 'OneDrive Web' }
        dcad865d-9257-4521-ad4d-bae3e137b345 { $return = 'Microsoft SharePoint Online - SharePoint Home' }
        b2cc270f-563e-4d8a-af47-f00963a71dcd { $return = 'OneProfile Service' }
        4660504c-45b3-4674-a709-71951a6b0763 { $return = 'Microsoft Invitation Acceptance Portal' }
        ba23cd2a-306c-48f2-9d62-d3ecd372dfe4 { $return = 'OfficeGraph' }
        d52485ee-4609-4f6b-b3a3-68b6f841fa23 { $return = 'On-Premises Data Gateway Connector' }
        996def3d-b36c-4153-8607-a6fd3c01b89f { $return = 'Dynamics 365 for Financials' }
        b6b84568-6c01-4981-a80f-09da9a20bbed { $return = 'Microsoft Invoicing' }
        9d3e55ba-79e0-4b7c-af50-dc460b81dca1 { $return = 'Microsoft Azure Data Catalog' }
        4345a7b9-9a63-4910-a426-35363201d503 { $return = 'O365 Suite UX' }
        ac815d4a-573b-4174-b38e-46490d19f894 { $return = 'Workflow' }
        bb8f18b0-9c38-48c9-a847-e1ef3af0602d { $return = 'Microsoft.Azure.ActiveDirectoryIUX' }
        cc15fd57-2c6c-4117-a88c-83b1d56b4bbe { $return = 'Microsoft Teams Services' }
        5e3ce6c0-2b1f-4285-8d4b-75ee78787346 { $return = 'Skype Teams' }
        1fec8e78-bce4-4aaf-ab1b-5451cc387264 { $return = 'Microsoft Teams' }
        6d32b7f8-782e-43e0-ac47-aaad9f4eb839 { $return = 'Permission Service O365' }
        cdccd920-384b-4a25-897d-75161a4b74c1 { $return = 'Skype Teams Firehose' }
        1c0ae35a-e2ec-4592-8e08-c40884656fa5 { $return = 'Skype Team Substrate connector' }
        cf6c77f8-914f-4078-baef-e39a5181158b { $return = 'Skype Teams Settings Store' }
        64f79cb9-9c82-4199-b85b-77e35b7dcbcb { $return = 'Microsoft Teams Bots' }
        b7912db9-aa33-4820-9d4f-709830fdd78f { $return = 'ConnectionsService' }
        82f77645-8a66-4745-bcdf-9706824f9ad0 { $return = 'PowerApps Runtime Service' }
        6204c1d1-4712-4c46-a7d9-3ed63d992682 { $return = 'Microsoft Flow Portal' }
        7df0a125-d3be-4c96-aa54-591f83ff541c { $return = 'Microsoft Flow Service' }
        331cc017-5973-4173-b270-f0042fddfd75 { $return = 'PowerAppsService' }
        0a0e9e37-25e3-47d4-964c-5b8237cad19a { $return = 'CloudSponge' }
        df09ff61-2178-45d8-888c-4210c1c7b0b2 { $return = 'O365 UAP Processor' }
        8338dec2-e1b3-48f7-8438-20c30a534458 { $return = 'ViewPoint' }
        00000001-0000-0000-c000-000000000000 { $return = 'Azure ESTS Service' }
        394866fc-eedb-4f01-8536-3ff84b16be2a { $return = 'Microsoft People Cards Service' }
        0a0a29f9-0a25-49c7-94bf-c53c3f8fa69d { $return = 'Cortana Experience with O365' }
        bb2a2e3a-c5e7-4f0a-88e0-8e01fd3fc1f4 { $return = 'CPIM Service' }
        0004c632-673b-4105-9bb6-f3bbd2a927fe { $return = 'PowerApps and Flow' }
        d3ce4cf8-6810-442d-b42e-375e14710095 { $return = 'Graph Explorer' }
        3aa5c166-136f-40eb-9066-33ac63099211 { $return = 'O365 Customer Monitoring' }
        d6fdaa33-e821-4211-83d0-cf74736489e1 { $return = 'Microsoft Service Trust' }
        ef4a2a24-4b4e-4abf-93ba-cc11c5bd442c { $return = 'Edmodo' }
        b692184e-b47f-4706-b352-84b288d2d9ee { $return = 'Microsoft.MileIQ.RESTService' }
        a25dbca8-4e60-48e5-80a2-0664fdb5c9b6 { $return = 'Microsoft.MileIQ' }
        f7069a8d-9edc-4300-b365-ae53c9627fc4 { $return = 'Microsoft.MileIQ.Dashboard' }
        02e3ae74-c151-4bda-b8f0-55fbf341de08 { $return = 'Application Registration Portal' }
        1f5530b3-261a-47a9-b357-ded261e17918 { $return = 'Azure Multi-Factor Auth Connector' }
        981f26a1-7f43-403b-a875-f8b09b8cd720 { $return = 'Azure Multi-Factor Auth Client' }
        6ea8091b-151d-447a-9013-6845b83ba57b { $return = 'AD Hybrid Health' }
        fc68d9e5-1f76-45ef-99aa-214805418498 { $return = 'Azure AD Identity Protection' }
        01fc33a7-78ba-4d2f-a4b7-768e336e890e { $return = 'MS-PIM' }
        a6aa9161-5291-40bb-8c5c-923b567bee3b { $return = 'Storage Resource Provider' }
        4e9b8b9a-1001-4017-8dd1-6e8f25e19d13 { $return = 'Adobe Acrobat' }
        159b90bb-bb28-4568-ad7c-adad6b814a2f { $return = 'LastPass' }
        b4bddae8-ab25-483e-8670-df09b9f1d0ea { $return = 'Signup' }
        aa580612-c342-4ace-9055-8edee43ccb89 { $return = 'Microsoft StaffHub' }
        51133ff5-8e0d-4078-bcca-84fb7f905b64 { $return = 'Microsoft Teams Mailhook' }
        ab3be6b7-f5df-413d-ac2d-abf1e3fd9c0b { $return = 'Microsoft Teams Graph Service' }
        b1379a75-ce5e-4fa3-80c6-89bb39bf646c { $return = 'Microsoft Teams Chat Aggregator' }
        48af08dc-f6d2-435f-b2a7-069abd99c086 { $return = 'Connectors' }
        d676e816-a17b-416b-ac1a-05ad96f43686 { $return = 'Workflow' }
        cfa8b339-82a2-471a-a3c9-0fc0be7a4093 { $return = 'Azure Key Vault' }
        c2f89f53-3971-4e09-8656-18eed74aee10 { $return = 'calendly' }
        6da466b6-1d13-4a2c-97bd-51a99e8d4d74 { $return = 'Exchange Office Graph Client for AAD - Interactive' }
        0eda3b13-ddc9-4c25-b7dd-2f6ea073d6b7 { $return = 'Microsoft Flow CDS Integration Service' }
        eacba838-453c-4d3e-8c6a-eb815d3469a3 { $return = 'Microsoft Flow CDS Integration Service TIP1' }
        4ac7d521-0382-477b-b0f8-7e1d95f85ca2 { $return = 'SQL Server Analysis Services Azure' }
        b4114287-89e4-4209-bd99-b7d4919bcf64 { $return = 'OfficeDelve' }
        4580fd1d-e5a3-4f56-9ad1-aab0e3bf8f76 { $return = 'Call Recorder' }
        a855a166-fd92-4c76-b60d-a791e0762432 { $return = 'Microsoft Teams VSTS' }
        c37c294f-eec8-47d2-b3e2-fc3daa8f77d3 { $return = 'Workflow' }
        fc75330b-179d-49af-87dd-3b1acf6827fa { $return = 'AzureAutomationAADPatchS2S' }
        766d89a4-d6a6-444d-8a5e-e1a18622288a { $return = 'OneDrive' }
        f16c4a38-5aff-4549-8199-ee7d3c5bd8dc { $return = 'Workflow' }
        4c4f550b-42b2-4a16-93f9-fdb9e01bb6ed { $return = 'Targeted Messaging Service' }
        765fe668-04e7-42ba-aec0-2c96f1d8b652 { $return = 'Exchange Office Graph Client for AAD - Noninteractive' }
        0130cc9f-7ac5-4026-bd5f-80a08a54e6d9 { $return = 'Azure Data Warehouse Polybase' }
        a1cf9e0a-fe14-487c-beb9-dd3360921173 { $return = 'Meetup' }
        76cd24bf-a9fc-4344-b1dc-908275de6d6d { $return = 'Azure SQL Virtual Network to Network Resource Provider' }
        9f505dbd-a32c-4685-b1c6-72e4ef704cb0 { $return = 'Amazon Alexa' }
        1e2ca66a-c176-45ea-a877-e87f7231e0ee { $return = 'Microsoft B2B Admin Worker' }
        2634dd23-5e5a-431c-81ca-11710d9079f4 { $return = 'Microsoft Stream Service' }
        cf53fce8-def6-4aeb-8d30-b158e7b1cf83 { $return = 'Microsoft Stream Portal' }
        c9a559d2-7aab-4f13-a6ed-e7e9c52aec87 { $return = 'Microsoft Forms' }
        978877ea-b2d6-458b-80c7-05df932f3723 { $return = 'Microsoft Teams AuditService' }
        dbc36ae1-c097-4df9-8d94-343c3d091a76 { $return = 'Service Encryption' }
        fa7ff576-8e31-4a58-a5e5-780c1cd57caa { $return = 'OneNote' }
        cb4dc29f-0bf4-402a-8b30-7511498ed654 { $return = 'Power BI Premium' }
        f5aeb603-2a64-4f37-b9a8-b544f3542865 { $return = 'Microsoft Teams RetentionHook Service' }
        da109bdd-abda-4c06-8808-4655199420f8 { $return = 'Glip Contacts' }
        76c7f279-7959-468f-8943-3954880e0d8c { $return = 'Azure SQL Managed Instance to Microsoft.Network' }
        3a9ddf38-83f3-4ea1-a33a-ecf934644e2d { $return = 'Protected Message Viewer' }
        5635d99c-c364-4411-90eb-764a511b5fdf { $return = 'Responsive Banner Slider' }
        a43e5392-f48b-46a4-a0f1-098b5eeb4757 { $return = 'Cloudsponge' }
        d73f4b35-55c9-48c7-8b10-651f6f2acb2e { $return = 'MCAPI Authorization Prod' }
        166f1b03-5b19-416f-a94b-1d7aa2d247dc { $return = 'Office Hive' }
        b815ce1c-748f-4b1e-9270-a42c1fa4485a { $return = 'Workflow' }
        bd7b778b-4aa8-4cde-8d90-8aeb821c0bd2 { $return = 'Workflow' }
        9d06afd9-66c9-49a6-b385-ea7509332b0b { $return = 'O365SBRM Service' }
        9ea1ad79-fdb6-4f9a-8bc3-2b70f96e34c7 { $return = 'Bing' }
        57fb890c-0dab-4253-a5e0-7188c88b2bb4 { $return = 'SharePoint Online Client' }
        45c10911-200f-4e27-a666-9e9fca147395 { $return = 'drawio' }
        b73f62d0-210b-4396-a4c5-ea50c4fab79b { $return = 'Skype Business Voice Fraud Detection and Prevention' }
        bc59ab01-8403-45c6-8796-ac3ef710b3e3 { $return = 'Outlook Online Add-in App' }
        035f9e1d-4f00-4419-bf50-bf2d87eb4878 { $return = 'Azure Monitor Restricted' }
        7c33bfcb-8d33-48d6-8e60-dc6404003489 { $return = 'Network Watcher' }
        a0be0c72-870e-46f0-9c49-c98333a996f7 { $return = 'AzureDnsFrontendApp' }
        1e3e4475-288f-4018-a376-df66fd7fac5f { $return = 'NetworkTrafficAnalyticsService' }
        7557eb47-c689-4224-abcf-aef9bd7573df { $return = 'Skype for Business' }
        c39c9bac-9d1f-4dfb-aa29-27f6365e5cb7 { $return = 'Azure Advisor' }
        2087bd82-7206-4c0a-b305-1321a39e5926 { $return = 'Microsoft To-Do' }
        f8d98a96-0999-43f5-8af3-69971c7bb423 { $return = 'iOS Accounts' }
        c27373d3-335f-4b45-8af9-fe81c240d377 { $return = 'P2P Server' }
        5c2ffddc-f1d7-4dc3-926e-3c1bd98e32bd { $return = 'RITS Dev' }
        982bda36-4632-4165-a46a-9863b1bbcf7d { $return = 'O365 Demeter' }
        98c8388a-4e86-424f-a176-d1288462816f { $return = 'OfficeFeedProcessors' }
        bf9fc203-c1ff-4fd4-878b-323642e462ec { $return = 'Jarvis Transaction Service' }
        257601fd-462f-4a21-b623-7f719f0f90f4 { $return = 'Centralized Deployment' }
        2a486b53-dbd2-49c0-a2bc-278bdfc30833 { $return = 'Cortana at Work Service' }
        22d7579f-06c2-4baa-89d2-e844486adb9d { $return = 'Cortana at Work Bing Services' }
        4c8f074c-e32b-4ba7-b072-0f39d71daf51 { $return = 'IPSubstrate' }
        a164aee5-7d0a-46bb-9404-37421d58bdf7 { $return = 'Microsoft Teams AuthSvc' }
        354b5b6d-abd6-4736-9f51-1be80049b91f { $return = 'Microsoft Mobile Application Management Backend' }
        82b293b2-d54d-4d59-9a95-39c1c97954a7 { $return = 'Tasks in a Box' }
        fdc83783-b652-4258-a622-66bc85f1a871 { $return = 'FedExPackageTracking' }
        d0597157-f0ae-4e23-b06c-9e65de434c4f { $return = 'Microsoft Teams Task Service' }
        f5c26e74-f226-4ae8-85f0-b4af0080ac9e { $return = 'Application Insights API' }
        57c0fc58-a83a-41d0-8ae9-08952659bdfd { $return = 'Azure Cosmos DB Virtual Network To Network Resource Provider' }
        744e50be-c4ff-4e90-8061-cd7f1fabac0b { $return = 'LinkedIn Microsoft Graph Connector' }
        823dfde0-1b9a-415a-a35a-1ad34e16dd44 { $return = 'Microsoft Teams Wiki Images Migration' }
        3ab9b3bc-762f-4d62-82f7-7e1d653ce29f { $return = 'Microsoft Volume Licensing' }
        44eb7794-0e11-42b6-800b-dc31874f9f60 { $return = 'Alignable' }
        c58637bb-e2e1-4312-8a00-04b5ffcd3403 { $return = 'SharePoint Online Client Extensibility' }
        62b732f7-fc71-40bc-b27d-35efcb0509de { $return = 'Microsoft Teams AadSync' }
        07978fee-621a-42df-82bb-3eabc6511c26 { $return = 'SurveyMonkey' }
        47ee738b-3f1a-4fc7-ab11-37e4822b007e { $return = 'Azure AD Application Proxy' }
        00000007-0000-0000-c000-000000000000 { $return = 'Dynamics CRM Online' }
        913c6de4-2a4a-4a61-a9ce-945d2b2ce2e0 { $return = 'Dynamics Lifecycle services' }
        f217ad13-46b8-4c5b-b661-876ccdf37302 { $return = 'Attach OneDrive files to Asana' }
        00000008-0000-0000-c000-000000000000 { $return = 'Microsoft.Azure.DataMarket' }
        9b06ebd4-9068-486b-bdd2-dac26b8a5a7a { $return = 'Microsoft.DynamicsMarketing' }
        e8ab36af-d4be-4833-a38b-4d6cf1cfd525 { $return = 'Microsoft Social Engagement' }
        8909aac3-be91-470c-8a0b-ff09d669af91 { $return = 'Microsoft Parature Dynamics CRM' }
        71234da4-b92f-429d-b8ec-6e62652e50d7 { $return = 'Microsoft Customer Engagement Portal' }
        b861dbcc-a7ef-4219-a005-0e4de4ea7dcf { $return = 'Data Export Service for Microsoft Dynamics 365' }
        2db8cb1d-fb6c-450b-ab09-49b6ae35186b { $return = 'Microsoft Dynamics CRM Learning Path' }
        2e49aa60-1bd3-43b6-8ab6-03ada3d9f08b { $return = 'Dynamics Data Integration' }
    }

    if ([string]::IsNullOrEmpty($return)) {
        $return = $Applications | ? { $_.Appid -eq $ID } | Select -ExpandProperty DisplayName 
    }

    if ([string]::IsNullOrEmpty($return)) {
        $return = $Applications | ? { $_.ID -eq $ID } | Select -ExpandProperty DisplayName 
    }

    if ([string]::IsNullOrEmpty($return)) {
        $return = ''
    }

    return $return
}



$ConditionalAccessPolicyOutput = (Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/identity/conditionalAccess/policies" -Headers $Headers -Method Get -ContentType "application/json").value
(Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/groups" -Headers $Headers -Method Get -ContentType "application/json").value
$AllNamedLocations = (Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/identity/conditionalAccess/namedLocations" -Headers $Headers -Method Get -ContentType "application/json").value
$AllApplications = (Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/applications" -Headers $Headers -Method Get -ContentType "application/json").value
$AllRoleDefinitions = (Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/roleManagement/directory/roleDefinitions" -Headers $Headers -Method Get -ContentType "application/json").value
$GroupListOutput = (Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/groups" -Headers $Headers -Method Get -ContentType "application/json").value
$UserListOutput = (Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/users" -Headers $Headers -Method Get -ContentType "application/json").value | Select-Object * -ExcludeProperty *extensionAttribute*

$CAPolicyObj = foreach ($cap in $ConditionalAccessPolicyOutput) {
   [PSCustomObject]@{
        id                                          = $cap.id
        displayName                                 = $cap.displayName
        customer                                    = $cap.Customer
        tenantID                                    = $cap.TenantID
        createdDateTime                             = $(if (![string]::IsNullOrEmpty($cap.createdDateTime)) { [datetime]$cap.createdDateTime | Get-Date -Format "yyyy-MM-dd HH:mm" }else { "" })
        modifiedDateTime                            = $(if (![string]::IsNullOrEmpty($cap.modifiedDateTime)) { [datetime]$cap.modifiedDateTime | Get-Date -Format "yyyy-MM-dd HH:mm" }else { "" })
        state                                       = $cap.state
        clientAppTypes                              = ($cap.conditions.clientAppTypes) -join ","
        includePlatforms                            = ($cap.conditions.platforms.includePlatforms) -join ","
        excludePlatforms                            = ($cap.conditions.platforms.excludePlatforms) -join ","
        includeLocations                            = (Get-LocationNameFromId -Locations $AllNamedLocations -id $cap.conditions.locations.includeLocations) -join ","
        excludeLocations                            = (Get-LocationNameFromId -Locations $AllNamedLocations -id $cap.conditions.locations.excludeLocations) -join ","
        includeApplications                         = ($cap.conditions.applications.includeApplications | % { Get-ApplicationNameFromId -Applications $AllApplications -id $_ }) -join ","
        excludeApplications                         = ($cap.conditions.applications.excludeApplications | % { Get-ApplicationNameFromId -Applications $AllApplications -id $_ }) -join ","
        includeUserActions                          = ($cap.conditions.applications.includeUserActions | out-string)
        includeAuthenticationContextClassReferences = ($cap.conditions.applications.includeAuthenticationContextClassReferences | out-string)
        includeUsers                                = ($cap.conditions.users.includeUsers | % { Get-UserNameFromId -Users $UserListOutput -id $_ }) -join(" ")
        excludeUsers                                = ($cap.conditions.users.excludeUsers | % { Get-UserNameFromId -Users $UserListOutput -id $_ }) -join(" ")
        includeGroups                               = ($cap.conditions.users.includeGroups | % { Get-GroupNameFromId -Groups $GroupListOutput -id $_ }) -join(" ")
        excludeGroups                               = ($cap.conditions.users.excludeGroups | % { Get-GroupNameFromId -Groups $GroupListOutput -id $_ }) -join(" ")
        includeRoles                                = ($cap.conditions.users.includeRoles | % { Get-RoleNameFromId -RoleDefinitions $AllRoleDefinitions -id $_ })
        excludeRoles                                = ($cap.conditions.users.excludeRoles | % { Get-RoleNameFromId -RoleDefinitions $AllRoleDefinitions -id $_ })
        grantControlsOperator                       = ($cap.grantControls.operator) -join ","
        builtInControls                             = ($cap.grantControls.builtInControls) -join ","
        customAuthenticationFactors                 = ($cap.grantControls.customAuthenticationFactors) -join ","
        termsOfUse                                  = ($cap.grantControls.termsOfUse) -join ","
    }
}
Write-Host "Getting Named Locations" -ForegroundColor Green
$NamedLocations = foreach ($locations in $AllNamedLocations) {
    [PSCustomObject]@{
      displayname                       = $locations.displayName
      modifiedDateTime                  = $locations.modifiedDateTime
      createdDateTime                   = $locations.createdDateTime
      isTrusted                         = if($locations.isTrusted){$locations.isTrusted}else{$false}
      ipRanges                          = if($locations.ipRanges){$locations.ipRanges.cidrAddress -join ", "}else{"N/A"}
      countriesAndRegions               = if($locations.countriesAndRegions){$locations.countriesAndRegions}else{"N/A"}
      includeUnknownCountriesAndRegions = if($locations.includeUnknownCountriesAndRegions){$locations.includeUnknownCountriesAndRegions}else{"N/A"} 
      countryLookupMethod               = if($locations.countryLookupMethod){$locations.countryLookupMethod}else{"N/A"}
    }
  }
}catch{"This client does not have a Azure AD P1 subscription or the app registration does not have the necessary permissions"
write-host $_}



####INTUNE#############

#####App Protection Policies#####

##Windows Information Protection-WithoutEnrollment#### 
try{
    Write-Host "Getting WIP Policies" -ForegroundColor Green
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
  


#Define CSV Path 
$path = echo ([Environment]::GetFolderPath("Desktop")+"\Microsoft_${customerDomain}_OrgReports")
New-Item -ItemType Directory -Force -Path $path
##Legacy Auth CSV Path
if($LegacyAuthSettings){
    $LegacyAuthSettingsReport = echo ([Environment]::GetFolderPath("Desktop")+"\Microsoft_${customerDomain}_OrgReports\LegacyAuthSettings.csv")
    $LegacyAuthSettings | Export-CSV -Path $LegacyAuthSettingsReport -NoTypeInformation -Append
}
##Legacy Auth Signin CSV Path
if($LegacyAuthSignIn){
$LegacyAuthSignInsReport = echo ([Environment]::GetFolderPath("Desktop")+"\Microsoft_${customerDomain}_OrgReports\LegacyAuthSignIn.csv")
$LegacyAuthSignIn | Export-CSV -Path $LegacyAuthSignInsReport -NoTypeInformation -Append
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
##ConditionalAccessPolicies CSV Path
if($CAPolicyObj){
$CAReport = echo ([Environment]::GetFolderPath("Desktop")+"\Microsoft_${customerDomain}_OrgReports\ConditionalAccessPolicies.csv")
$CAPolicyObj | Export-CSV -Path $CAReport  -NoTypeInformation -Append
}
##Named Locations CSV Path
if($NamedLocations){
$NamedLocationReport = echo ([Environment]::GetFolderPath("Desktop")+"\Microsoft_${customerDomain}_OrgReports\NamedLocations.csv")
$NamedLocations | Export-CSV -Path $NamedLocationReport  -NoTypeInformation -Append
}
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
$outputfilename = "$path\$(${customerDomain})_orgsettgings.xlsx"
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
