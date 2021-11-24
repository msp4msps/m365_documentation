<#
  .SYNOPSIS
  This script is used to garner sharepoint site information across all customers and output that information to a CSV file
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
 
    Write-Host "Getting group info for $($customer.name)"

    ##Get Access Token########
    $CustomerToken = New-PartnerAccessToken -ApplicationId $ApplicationId -Credential $credential -RefreshToken $refreshToken -Scopes 'https://graph.microsoft.com/.default' -Tenant $customer.TenantID
    $headers = @{ "Authorization" = "Bearer $($CustomerToken.AccessToken)" }
    
    ##GET DOMAIN 
    $customerDomain = (Get-MsolDomain -TenantId $customer.TenantID | Where-Object {$_.isDefault}).name

    #Define CSV Path 
$path = echo ([Environment]::GetFolderPath("Desktop")+"\MicrosoftSharePointReports")
New-Item -ItemType Directory -Force -Path $path
$customerSharePointReport = echo ([Environment]::GetFolderPath("Desktop")+"\MicrosoftSharePointReports\${customerDomain}.csv")

#####Get Group information if it is available####
try{
$Sites = (Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/reports/getSharePointSiteUsageDetail(period='D30')" -Headers $headers -Method Get -ContentType "application/json") | convertfrom-csv  |select-object @{ Name = 'Site Name'; Expression = { $_.'Site URL'.split('/')[4] } },
@{ Name = 'Site URL'; Expression = { $_.'Site URL' } },
@{ Name = 'Site Last Activity Date'; Expression = { $_.'Last Activity Date' } },
@{ Name = 'Site File Count'; Expression = { $_.'File Count' } },
@{ Name = 'Site Storage Used (GB)'; Expression = { [math]::round($_.'Storage Used (Byte)' /1GB,0) } },
@{ Name = 'Storage Allocated (GB)'; Expression = { [math]::round($_.'Storage Allocated (Byte)' /1GB,0) } },
@{ Name = 'Microsoft Group connect'; Expression = { $_.'Root Web Template' } }
}catch{('Error calling sites MS Graph')} 



if($Sites){

  $SharePointObj = foreach ($site in $Sites) {
  
    [PSCustomObject]@{
      'Site Name'                          = $site.'Site Name'
      "Site URL"                           = $site.'Site URL'
      "Last Activity Date"                 = $site.'Site Last Activity Date'
      'Site File Count'                    = $site.'Site File Count'
      "Site Storage Used (GB)"             = $site.'Site Storage Used (GB)'
      "Storage Allocated (GB)"             = $site.'Storage Allocated (GB)'
      "Microsoft Group Connected"          = if($site.'Microsoft Group connect' -eq "Group"){$true}else{$false}
  
  }
    
  }
  
  
  $SharePointObj| Export-CSV -Path $customerSharePointReport -NoTypeInformation -Append   
}

}