<#
  .SYNOPSIS
  This script is used to garner user information across all customers and output that information to a CSV file
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


$aadGraphToken = New-PartnerAccessToken -ApplicationId $ApplicationId -Credential $credential -RefreshToken $refreshToken -Scopes 'https://graph.windows.net/.default' -ServicePrincipal -Tenant $tenantID
$graphToken = New-PartnerAccessToken -ApplicationId $ApplicationId -Credential $credential -RefreshToken $refreshToken -Scopes 'https://graph.microsoft.com/.default' -ServicePrincipal -Tenant $tenantID


Connect-MsolService -AdGraphAccessToken $aadGraphToken.AccessToken -MsGraphAccessToken $graphToken.AccessToken


function Get-MSGraph($uri){
  $response = (Invoke-RestMethod -Uri $uri -Method Get -ContentType "application/json" -Headers $headers)
  return $response
}


$graphApiVersion = "Beta"
$App_resource = "users?top=999&select=displayName,userPrincipalName,signInActivity,createdDateTime,accountEnabled,assignedLicenses,givenName,surname,jobtitle,mail"
$AccountSkuIdDecodeData = @{
  "SPB"                                = "Micorsoft 365 Business Premium"
  "SMB_BUSINESS"                       = "MICROSOFT 365 APPS FOR BUSINESS"
  "SMB_BUSINESS_ESSENTIALS"            = "MICROSOFT 365 BUSINESS BASIC"
  "M365_F1"                            = "Microsoft 365 F1"
  "O365_BUSINESS_ESSENTIALS"           = "MICROSOFT 365 BUSINESS BASIC"
  "O365_BUSINESS_PREMIUM"              = "MICROSOFT 365 BUSINESS STANDARD"
  "DESKLESSPACK"                       = "OFFICE 365 F3"
  "TEAMS_FREE"                         = "MICROSOFT TEAM (FREE)"
  "TEAMS_EXPLORATORY"                  = "MICROSOFT TEAMS EXPLORATORY" 
  "M365EDU_A3_STUDENT"                 = "MICROSOFT 365 A3 FOR STUDENTS"
  "M365EDU_A5_STUDENT"                 = "MICROSOFT 365 A5 FOR STUDENTS"
  "M365EDU_A3_FACULTY"                 = "MICROSOFT 365 A3 FOR FACULTY"
  "M365EDU_A5_FACULTY"                 = "MICROSOFT 365 A5 FOR FACULTY"
  "MCOEV_FACULTY"                      = "MICROSOFT 365 PHONE SYSTEM FOR FACULTY"
  "MCOEV_STUDENT"                      = "MICROSOFT 365 PHONE SYSTEM FOR STUDENTS"
  "ENTERPRISEPREMIUM_STUDENT"          = "Office 365 A5 for students"
  "ENTERPRISEPREMIUM_FACULTY"          = "Office 365 A5 for faculty"
  "M365EDU_A1"                         = "Microsoft 365 A1"
  "SHAREPOINTSTANDARD"                 = "SHAREPOINT ONLINE (PLAN 1)"
  "SHAREPOINTENTERPRISE"               = "SHAREPOINT ONLINE (PLAN 2)" 
  "EXCHANGEDESKLESS"                   = "EXCHANGE ONLINE KIOSK"
  "LITEPACK"                           = "OFFICE 365 SMALL BUSINESS"
  "EXCHANGESTANDARD"                   = "EXCHANGE ONLINE (PLAN 1)"
  "STANDARDPACK"                       = "OFFICE 365 E1"
  "STANDARDWOFFPACK"                   = "Office 365 (Plan E2)"
  "ENTERPRISEPACK"                     = "OFFICE 365 E3"
  "VISIOCLIENT"                        = "Visio Pro Online"
  "POWER_BI_ADDON"                     = "Office 365 Power BI Addon"
  "POWER_BI_INDIVIDUAL_USE"            = "Power BI Individual User"
  "POWER_BI_STANDALONE"                = "Power BI Stand Alone"
  "POWER_BI_STANDARD"                  = "Power-BI Standard"
  "PROJECTESSENTIALS"                  = "Project Lite"
  "PROJECTCLIENT"                      = "Project Professional"
  "PROJECTONLINE_PLAN_1"               = "Project Online"
  "PROJECTONLINE_PLAN_2"               = "Project Online and PRO"
  "ProjectPremium"                     = "Project Online Premium"
  "EMS"                                = "ENTERPRISE MOBILITY + SECURITY E3"
  "EMSPREMIUM"                         = "ENTERPRISE MOBILITY + SECURITY E5"
  "RIGHTSMANAGEMENT"                   = "AZURE INFORMATION PROTECTION PLAN 1"
  "MCOMEETADV"                         = "Microsoft 365 Audio Conferencing"
  "BI_AZURE_P1"                        = "POWER BI FOR OFFICE 365 ADD-ON"
  "INTUNE_A"                           = "INTUNE"
  "WIN_DEF_ATP"                        = "Microsoft Defender Advanced Threat Protection"
  "IDENTITY_THREAT_PROTECTION"         =  "Microsoft 365 E5 Security"
  "IDENTITY_THREAT_PROTECTION_FOR_EMS_E5" = "Microsoft 365 E5 Security for EMS E5"
  "ATP_ENTERPRISE"                     = "Office 365 Advanced Threat Protection (Plan 1)"
  "EQUIVIO_ANALYTICS"                  = "Office 365 Advanced eDiscovery"
  "AAD_BASIC"                          = "Azure Active Directory Basic"
  "RMS_S_ENTERPRISE"                   = "Azure Active Directory Rights Management"
  "AAD_PREMIUM"                        = "Azure Active Directory Premium"
  "STANDARDPACK_GOV"                   = "Microsoft Office 365 (Plan G1) for Government"
  "M365_G3_GOV"                        = "MICROSOFT 365 GCC G3"
  "ENTERPRISEPACK_USGOV_DOD"           = "Office 365 E3_USGOV_DOD"
  "ENTERPRISEPACK_USGOV_GCCHIGH"       = "Office 365 E3_USGOV_GCCHIGH"
  "ENTERPRISEPACK_GOV"                 = "OFFICE 365 GCC G3"
  "SHAREPOINTLITE"                     = "SharePoint Online (Plan 1)"
  "MCOIMP"                             = "SKYPE FOR BUSINESS ONLINE (PLAN 1)"
  "OFFICESUBSCRIPTION"                 = "MICROSOFT 365 APPS FOR ENTERPRISE"
  "YAMMER_MIDSIZE"                     = "Yammer"
  "DYN365_ENTERPRISE_PLAN1"            = "Dynamics 365 Customer Engagement Plan Enterprise Edition"
  "ENTERPRISEPREMIUM_NOPSTNCONF"       = "Enterprise E5 (without Audio Conferencing)"
  "ENTERPRISEPREMIUM"                  = "Enterprise E5 (with Audio Conferencing)"
  "MCOSTANDARD"                        = "Skype for Business Online Standalone Plan 2"
  "PROJECT_MADEIRA_PREVIEW_IW_SKU"     = "Dynamics 365 for Financials for IWs"
  "EOP_ENTERPRISE_FACULTY"             = "Exchange Online Protection for Faculty"
  "DYN365_FINANCIALS_BUSINESS_SKU"     = "Dynamics 365 for Financials Business Edition"
  "DYN365_FINANCIALS_TEAM_MEMBERS_SKU" = "Dynamics 365 for Team Members Business Edition"
  "FLOW_FREE"                          = "Microsoft Flow Free"
  "POWER_BI_PRO"                       = "Power BI Pro"
  "O365_BUSINESS"                      = "MICROSOFT 365 APPS FOR BUSINESS"
  "DYN365_ENTERPRISE_SALES"            = "Dynamics Office 365 Enterprise Sales"
  "PROJECTPROFESSIONAL"                = "Project Professional"
  "VISIOONLINE_PLAN1"                  = "Visio Online Plan 1"
  "EXCHANGEENTERPRISE"                 = "Exchange Online Plan 2"
  "DYN365_ENTERPRISE_P1_IW"            = "Dynamics 365 P1 Trial for Information Workers"
  "DYN365_ENTERPRISE_TEAM_MEMBERS"     = "Dynamics 365 For Team Members Enterprise Edition"
  "CRMSTANDARD"                        = "Microsoft Dynamics CRM Online Professional"
  "EXCHANGEARCHIVE_ADDON"              = "Exchange Online Archiving For Exchange Online"
  "SPZA_IW"                            = "App Connect"
  "WINDOWS_STORE"                      = "Windows Store for Business"
  "MCOEV"                              = "Microsoft Phone System"
  "MCOEV_GOV"                          = "MICROSOFT 365 PHONE SYSTEM FOR GCC"
  "SPE_E5"                             = "Microsoft 365 E5"
  "SPE_E3"                             = "Microsoft 365 E3"
  "MCOPSTN1"                           = "PSTN DOMESTIC CALLING"
  "MCOPSTN2"                           = "Domestic and International Calling Plan"
  "MCOPSTN_"                           = "MICROSOFT 365 DOMESTIC CALLING PLAN (120 Minutes)"
  "DYN365_TEAM_MEMBERS"                = "Dynamics 365 Team Members"
  "WIN10_PRO_ENT_SUB"                  = "WINDOWS 10 ENTERPRISE E3"
  "WIN10_VDA_E3"                       = "WINDOWS 10 ENTERPRISE E3"
  "WIN10_VDA_E5"                       = "Windows 10 Enterprise E5"
  "MDATP_XPLAT"                        = "Microsoft Defender for Endpoint"
  "CCIBOTS_PRIVPREV_VIRAL"             = "Power Virtual Agents Viral Trial"
  "ADALLOM_STANDALONE"                 = "Microsoft Cloud App Security"
  "BUSINESS_VOICE_MED2_TELCO"          = "Microsoft 365 Business Voice (US)"

}


Write-Host "Found $($customers.Count) customers in Partner Center." -ForegroundColor DarkGreen

  foreach ($customer in $customers) {
    
    Write-Host "Found $($customer.Name) in Partner Center" -ForegroundColor Green


    $CustomerToken = New-PartnerAccessToken -ApplicationId $ApplicationId -Credential $credential -RefreshToken $refreshToken -Scopes 'https://graph.microsoft.com/.default' -Tenant $customer.TenantID
    $headers = @{ "Authorization" = "Bearer $($CustomerToken.AccessToken)" }
  
  

          ##GET Microsoft Users Graph API###
          $uri = "https://graph.microsoft.com/$graphApiVersion/$($App_resource)"
          $userList = (Get-MSGraph -uri $uri).value
          ##GET Licenses Graph API###
          $Licenselist = (Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/subscribedSkus" -Headers $Headers -Method Get -ContentType "application/json").value
          $Licenselist | ForEach-Object { $_.skupartnumber = "$($AccountSkuIdDecodeData.$($_.skupartnumber))" }
          
            ##GET DOMAIN 
          $customerDomain = $userList[1].UserPrincipalName.split("@")[1];

          #Define CSV Path 
          $path = echo ([Environment]::GetFolderPath("Desktop")+"\MicrosoftUserReports")
          New-Item -ItemType Directory -Force -Path $path
          $customerUserReport = echo ([Environment]::GetFolderPath("Desktop")+"\MicrosoftUserReports\${customerDomain}.csv")

          ##GET EXCHANGE DATA 

          $ExchangeData = Get-MSGraph -uri "https://graph.microsoft.com/beta/reports/getMailboxUsageDetail(period='D30')" | convertfrom-csv | select-object @{ Name = 'UPN'; Expression = { $_.'User Principal Name' } },
          @{ Name = 'displayName'; Expression = { $_.'Display Name' } },
          @{ Name = 'LastActive'; Expression = { $_.'Last Activity Date' } },
          @{ Name = 'UsedGB'; Expression = { [math]::round($_.'Storage Used (Byte)' / 1GB, 0) } },
          @{ Name = 'ItemCount'; Expression = { $_.'Item Count' } },
          @{ Name = 'HasArchive'; Expression = { $_.'Has Archive' } }

          ##GET ONEDRIVE DATA

          $OneDriveData = Get-MSGraph -uri "https://graph.microsoft.com/beta/reports/getOneDriveUsageAccountDetail(period='D30')" | convertfrom-csv | select-object @{ Name = 'UPN'; Expression = { $_.'Owner Principal Name' } },
          @{ Name = 'displayName'; Expression = { $_.'Owner Display Name' } },
          @{ Name = 'LastActive'; Expression = { $_.'Last Activity Date' } },
          @{ Name = 'FileCount'; Expression = { $_.'File Count' } },
          @{ Name = 'UsedGB'; Expression = { [math]::round($_.'Storage Used (Byte)' /1GB,0) } },
          @{ Name = 'ODViewedOrEditedFileCount'; Expression = { $_.'Viewed Or Edited File Count' } },
          @{ Name = 'ODSyncedFileCount'; Expression = { $_.'Synced File Count' } },
          @{ Name = 'ODSharedInternallyFileCount'; Expression = { $_.'Shared Internally File Count' } },
          @{ Name = 'ODSharedExternallyFileCount'; Expression = { $_.'Shared Externally File Count' } }


          #GET SHAREPOINT DATA 

          $SharePointData = Get-MSGraph -uri "https://graph.microsoft.com/beta/reports/getSharePointActivityUserDetail(period='D30')" | convertfrom-csv | select-object @{ Name = 'UPN'; Expression = { $_.'User Principal Name' } },
          @{ Name = 'SharePointLastActive'; Expression = { $_.'Last Activity Date' } },
          @{ Name = 'SPViewedEditedFileCount'; Expression = { $_.'Viewed Or Edited File Count' } },
          @{ Name = 'SPSyncedFileCount'; Expression = { $_.'Synced File Count' } },
          @{ Name = 'SPSharedInternallyFileCount'; Expression = { $_.'Shared Internally File Count' } },
          @{ Name = 'SPSharedExternallyFileCount'; Expression = { $_.'Shared Externally File Count' } },
          @{ Name = 'VisitedPageCount'; Expression = { $_.'Visited Page Count' } }


          ##GET TEAMS DATA

          $TeamsData= Get-MSGraph -uri "https://graph.microsoft.com/beta/reports/getTeamsUserActivityUserDetail(period='D30')"  | convertfrom-csv | select-object @{ Name = 'UPN'; Expression = { $_.'User Principal Name' } },
          @{ Name = 'LastActive'; Expression = { $_.'Last Activity Date' } },
          @{ Name = 'TeamsChat'; Expression = { $_.'Team Chat Message Count' } },
          @{ Name = 'CallCount'; Expression = { $_.'Call Count' } },
          @{ Name = 'MeetingCount'; Expression = { $_.'Meeting Count' } }

           ###GET MFA DATA ###

          $uri = "https://graph.microsoft.com/beta/reports/credentialUserRegistrationDetails"
          try{
                $CAMFA = (Get-MSGraph -uri $uri).value
          } catch{
              write-host "Tenant does not have p1 licensing"
          }
          $PerUserMFA = Get-MsolUser -all -TenantId $customer.TenantID | Select-Object DisplayName,UserPrincipalName,@{N="MFA Status"; E={if( $_.StrongAuthenticationRequirements.State -ne $null) {$_.StrongAuthenticationRequirements.State} else { "Disabled"}}}

          $MFAList = $PerUserMFA | ForEach-Object {

              $MFARegUser = if (($CAMFA | Where-Object -Property UserPrincipalName -EQ $_.UserPrincipalName).IsMFARegistered -eq $null) { $false } else { ($CAMFA| Where-Object -Property UserPrincipalName -EQ $_.UserPrincipalName).IsMFARegistered }
              [PSCustomObject]@{
                  UPN             = $_.UserPrincipalName
                  PerUser         = $_.'MFA Status'
                  MFARegistration = $MFARegUser
                  TrueMFA         = if($_.'MFA Status' -eq 'Disabled' -and $MFAReguser -eq $false) {$false} else {$true}
                  }
              }
          
          ###Looping Through Users and Matching Data###
          $userObj = foreach($user in $userList){
            Write-Host "Getting User Settings for $($user.displayName)"
            ###GET Admin Roles###
            $userRole = (Get-MsolUserRole -TenantId $customer.TenantID -UserPrincipalName $user.userprincipalname).Name
            ###GET Password Config and AD Sync Status###
            $Msoline = Get-MsolUser -TenantId $customer.TenantID -UserPrincipalName $user.userprincipalname | Select-object LastDirSyncTime,LastPasswordChangeTimestamp,PasswordNeverExpires
            if(!$userRole){
              $userRole = "User"
            }
            if($Msoline.LastDirSyncTime){
              $hybridStatus = "Onprem"
            } else{
              $hybridStatus = "Cloud"
            }
            #Get Auth Methods
            $uri = "https://graph.microsoft.com/beta/users/$($user.userprincipalname)/authentication/emailMethods"
            $EmailMethods = (Get-MSGraph -uri $uri).value 
            $uri = "https://graph.microsoft.com/beta/users/$($user.userprincipalname)/authentication/phoneMethods"
            $PhoneMethods = (Get-MSGraph -uri $uri).value 

           [PSCustomObject]@{
              'DisplayName'                        = $user.displayname
              "FirstName"                          = $user.givenName
              "LastName"                           = $user.surname
              'UPN'                                = $user.userprincipalname
              "Role"                               = $userRole
              "JobTitle"                           = $user.jobTitle
              "LicensesAssigned"                   = ($Licenselist | Where-Object { $_.skuid -in $User.assignedLicenses.skuid }).skupartnumber -join "`n"
              "LastSignIn"                         = $user.signInActivity.lastSignInDateTime
              "createdDateTime"                    = $user.createdDateTime
              "accountEnabled"                     = $user.accountEnabled
              "AccountType"                        = $hybridStatus
              "LastPasswordChange"                 = $Msoline.LastPasswordChangeTimestamp
              "PasswordExpiration"                 = $Msoline.PasswordNeverExpires
              "MFARegistered"                      = ($MFAList | where-object { $_.UPN -eq $user.userPrincipalName}).TrueMFA
              "ExchangeLastActive"                 = ($ExchangeData | where-object { $_.UPN -eq $user.userPrincipalName}).LastActive
              "MailboxStorageUsedGB"               = ($ExchangeData | where-object { $_.UPN -eq $user.userPrincipalName}).UsedGB
              "MailboxItemCount"                   = ($ExchangeData | where-object { $_.UPN -eq $user.userPrincipalName}).ItemCount
              "HasArchive"                         = ($ExchangeData | where-object { $_.UPN -eq $user.userPrincipalName}).HasArchive
              "AuthMethod:Phone"                   = $PhoneMethods.phonenumber
              "AuthMethod:Email"                   = $EmailMethods.emailaddress
              "OneDriveLastActive"                 = ($OneDriveData | where-object { $_.UPN -eq $user.userPrincipalName}).LastActive
              "OneDriveStorageUsed"                = ($OneDriveData | where-object { $_.UPN -eq $user.userPrincipalName}).UsedGB
              "OneDriveFileCount"                  = ($OneDriveData | where-object { $_.UPN -eq $user.userPrincipalName}).FileCount
              "OneDriveViewed/EditedFileCount"     = ($OneDriveData  | where-object { $_.UPN -eq $user.userPrincipalName}).ODViewedOrEditedFileCount
              "OneDriveSyncedFileCount"            = ($OneDriveData| where-object { $_.UPN -eq $user.userPrincipalName}).ODSyncedFileCount
              "OneDriveSharedInternalFileCount"    = ($OneDriveData | where-object { $_.UPN -eq $user.userPrincipalName}).ODSharedInternallyFileCount
              "OneDriveSharedExternalFileCount"    = ($OneDriveData | where-object { $_.UPN -eq $user.userPrincipalName}).ODSharedExternallyFileCount
              "SharePointLastActive"               = ($SharePointData| where-object { $_.UPN -eq $user.userPrincipalName}).SharePointLastActive
              "SharePointViewed/EditedFileCount"   = ($SharePointData | where-object { $_.UPN -eq $user.userPrincipalName}).SPViewedEditedFileCount
              "SharePointSyncedFileCount"          = ($SharePointData | where-object { $_.UPN -eq $user.userPrincipalName}).SPSyncedFileCount
              "SharePointSharedInternalFileCount"  = ($SharePointData | where-object { $_.UPN -eq $user.userPrincipalName}).SPSharedInternallyFileCount
              "SharePointSharedExternalFileCount"  = ($SharePointData | where-object { $_.UPN -eq $user.userPrincipalName}).SPSharedExternallyFileCount
              "SharePointVisitedPageCount"         = ($SharePointData | where-object { $_.UPN -eq $user.userPrincipalName}).VisitedPageCount
              "TeamsLastActive"                    = ($TeamsData | where-object { $_.UPN -eq $user.userPrincipalName}).LastActive
              "TeamsChatCount"                     = ($TeamsData | where-object { $_.UPN -eq $user.userPrincipalName}).TeamsChat
              "TeamsCallCount"                     = ($TeamsData | where-object { $_.UPN -eq $user.userPrincipalName}).CallCount
              "TeamsMeetingCount"                  = ($TeamsData | where-object { $_.UPN -eq $user.userPrincipalName}).MeetingCount

          }
          }
          $userObj | Export-CSV -Path $customerUserReport -NoTypeInformation -Append 
  
  }