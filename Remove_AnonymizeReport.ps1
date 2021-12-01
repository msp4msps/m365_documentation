<#
  .SYNOPSIS
  This script is used de-anonymize reports in the 365 admin center for all customers. 
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
        [string]$ExchangeRefreshToken
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
$secPas = $ApplicationSecret| ConvertTo-SecureString -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($ApplicationId, $secPas)

###Connect to your Own Partner Center to get a list of customers/tenantIDs #########

$aadGraphToken = New-PartnerAccessToken -ApplicationId $ApplicationId -Credential $credential -RefreshToken $refreshToken -Scopes 'https://graph.windows.net/.default' -ServicePrincipal -Tenant $tenantID

$graphToken = New-PartnerAccessToken -ApplicationId $ApplicationId -Credential $credential -RefreshToken $refreshToken -Scopes 'https://graph.microsoft.com/.default' -ServicePrincipal -Tenant $tenantID

$customers = Get-MsolPartnerContract -All

 
Write-Host "Found $($customers.Count) customers in Partner Center." -ForegroundColor DarkGreen

Connect-MsolService -AdGraphAccessToken $aadGraphToken.AccessToken -MsGraphAccessToken $graphToken.AccessToken

foreach ($customer in $customers) {

write-Host "Turning off anonomized reporting for $($customer.name)"

try {
  $uri = "https://login.microsoftonline.com/$($customer.TenantID)/oauth2/token"
  $body = "resource=https://admin.microsoft.com&grant_type=refresh_token&refresh_token=$($ExchangeRefreshToken)"
  $token = Invoke-RestMethod $uri -Body $body -ContentType "application/x-www-form-urlencoded" -ErrorAction SilentlyContinue -Method post
  $AnonReports = Invoke-RestMethod -ContentType "application/json;charset=UTF-8" -Uri 'https://admin.microsoft.com/admin/api/reports/config/SetTenantConfiguration' -Body '{"PrivacyEnabled":false,"PowerBiEnabled":true}' -Method POST -Headers @{
      Authorization            = "Bearer $($token.access_token)";
      "x-ms-client-request-id" = [guid]::NewGuid().ToString();
      "x-ms-client-session-id" = [guid]::NewGuid().ToString()
      'x-ms-correlation-id'    = [guid]::NewGuid()
      'X-Requested-With'       = 'XMLHttpRequest' 
  } }catch { write-host "Could not configure this setting"}

}