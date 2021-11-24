Function Get-MFAStatus(){

 <#
  .SYNOPSIS
  This script is used to garner MFA information from a single tenant and output that information to a CSV file
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


$aadGraphToken = New-PartnerAccessToken -ApplicationId $ApplicationId -Credential $credential -RefreshToken $refreshToken -Scopes 'https://graph.windows.net/.default' -ServicePrincipal -Tenant $tenantID
$graphToken = New-PartnerAccessToken -ApplicationId $ApplicationId -Credential $credential -RefreshToken $refreshToken -Scopes 'https://graph.microsoft.com/.default' -ServicePrincipal -Tenant $tenantID


Connect-MsolService -AdGraphAccessToken $aadGraphToken.AccessToken -MsGraphAccessToken $graphToken.AccessToken


$CustomerToken = New-PartnerAccessToken -ApplicationId $ApplicationId -Credential $credential -RefreshToken $refreshToken -Scopes 'https://graph.microsoft.com/.default' -Tenant $customerTenantID

$headers = @{ "Authorization" = "Bearer $($CustomerToken.AccessToken)" }


function Get-MSGraph($uri){
  $response = (Invoke-RestMethod -Uri $uri -Method Get -ContentType "application/json" -Headers $headers)
  return $response
}


$uri = "https://graph.microsoft.com/beta/reports/credentialUserRegistrationDetails"
  try{
    $CAMFA = (Get-MSGraph -uri $uri).value
  } catch{
    write-host "Tenant does not have p1 licensing"
  }

  $PerUserMFA = Get-MsolUser -all -TenantId 1685b7a8-3883-44b8-b613-b9328c67c798 | Select-Object DisplayName,UserPrincipalName,@{N="MFA Status"; E={if( $_.StrongAuthenticationRequirements.State -ne $null) {$_.StrongAuthenticationRequirements.State} else { "Disabled"}}}

$customerDomain = $PerUserMFA[1].UserprincipalName.split("@")[1];
#Define CSV Path 
$path = echo ([Environment]::GetFolderPath("Desktop")+"\MFAReports")
New-Item -ItemType Directory -Force -Path $path
$customerMFAReport = echo ([Environment]::GetFolderPath("Desktop")+"\MFAReports\${customerDomain}.csv")

  $MFAList = $PerUserMFA | ForEach-Object {
  $MFARegUser = if (($CAMFA | Where-Object -Property UserPrincipalName -EQ $_.UserPrincipalName).IsMFARegistered -eq $null) { $false } else { ($CAMFA| Where-Object -Property UserPrincipalName -EQ $_.UserPrincipalName).IsMFARegistered }
  [PSCustomObject]@{
      UPN             = $_.UserPrincipalName
      PerUser         = $_.'MFA Status'
      MFARegistration = $MFARegUser
      TrueMFA         = if($_.'MFA Status' -eq 'Disabled' -and $MFAReguser -eq $false) {$false} else {$true}
      }
  }
  $MFAList 
  $MFAList | Export-CSV -Path $customerMFAReport -NoTypeInformation -Append 


}