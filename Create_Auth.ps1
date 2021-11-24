Param
(
    [Parameter(Mandatory = $false)]
    [switch]$ConfigurePreconsent,
    [Parameter(Mandatory = $true)]
    [string]$DisplayName,
    [Parameter(Mandatory = $false)]
    [string]$TenantId
)

$ErrorActionPreference = "Stop"

# Check if the Azure AD PowerShell module has already been loaded.
if ( ! ( Get-Module AzureAD ) ) {
    # Check if the Azure AD PowerShell module is installed.
    if ( Get-Module -ListAvailable -Name AzureAD ) {
        # The Azure AD PowerShell module is not load and it is installed. This module
        # must be loaded for other operations performed by this script.
        Write-Host -ForegroundColor Green "Loading the Azure AD PowerShell module..."
        Import-Module AzureAD
    } else {
        Install-Module AzureAD
    }
}

try {
    Write-Host -ForegroundColor Green "When prompted please enter the appropriate credentials... Warning: Window might have pop-under in VSCode"

    if([string]::IsNullOrEmpty($TenantId)) {
        Connect-AzureAD | Out-Null

        $TenantId = $(Get-AzureADTenantDetail).ObjectId
    } else {
        Connect-AzureAD -TenantId $TenantId | Out-Null
    }
} catch [Microsoft.Azure.Common.Authentication.AadAuthenticationCanceledException] {
    # The authentication attempt was canceled by the end-user. Execution of the script should be halted.
    Write-Host -ForegroundColor Yellow "The authentication attempt was canceled. Execution of the script will be halted..."
    Exit
} catch {
    # An unexpected error has occurred. The end-user should be notified so that the appropriate action can be taken.
    Write-Error "An unexpected error has occurred. Please review the following error message and try again." `
        "$($Error[0].Exception)"
}

$adAppAccess = [Microsoft.Open.AzureAD.Model.RequiredResourceAccess]@{
    ResourceAppId = "00000002-0000-0000-c000-000000000000";
    ResourceAccess =
    [Microsoft.Open.AzureAD.Model.ResourceAccess]@{
        Id = "5778995a-e1bf-45b8-affa-663a9f3f4d04";
        Type = "Role"},
    [Microsoft.Open.AzureAD.Model.ResourceAccess]@{
        Id = "a42657d6-7f20-40e3-b6f0-cee03008a62a";
        Type = "Scope"},
    [Microsoft.Open.AzureAD.Model.ResourceAccess]@{
        Id = "311a71cc-e848-46a1-bdf8-97ff7156d8e6";
        Type = "Scope"}
}

$graphAppAccess = [Microsoft.Open.AzureAD.Model.RequiredResourceAccess]@{
    ResourceAppId = "00000003-0000-0000-c000-000000000000";
    ResourceAccess =
        [Microsoft.Open.AzureAD.Model.ResourceAccess]@{
            Id = "9492366f-7969-46a4-8d15-ed1a20078fff";
            Type = "Role"},
        [Microsoft.Open.AzureAD.Model.ResourceAccess]@{
            Id = "7a6ee1e7-141e-4cec-ae74-d9db155731ff";
            Type = "Role"},
        [Microsoft.Open.AzureAD.Model.ResourceAccess]@{
            Id = "2f51be20-0bb4-4fed-bf7b-db946066c75e";
            Type = "Role"},
        [Microsoft.Open.AzureAD.Model.ResourceAccess]@{
            Id = "246dd0d5-5bd0-4def-940b-0421030a5b68";
            Type = "Role"},
        [Microsoft.Open.AzureAD.Model.ResourceAccess]@{
            Id = "bf394140-e372-4bf9-a898-299cfc7564e5";
            Type = "Role"},
        [Microsoft.Open.AzureAD.Model.ResourceAccess]@{
            Id = "19da66cb-0fb0-4390-b071-ebc76a349482";
            Type = "Role"},
        [Microsoft.Open.AzureAD.Model.ResourceAccess]@{
            Id = "656f6061-f9fe-4807-9708-6a2e0934df76";
            Type = "Role"},
        [Microsoft.Open.AzureAD.Model.ResourceAccess]@{
            Id = "230c1aed-a721-4c5d-9cb4-a90514e508ef";
            Type = "Role"},
        [Microsoft.Open.AzureAD.Model.ResourceAccess]@{
            Id = "7ab1d382-f21e-4acd-a863-ba3e13f7da61";
            Type = "Role"},
        [Microsoft.Open.AzureAD.Model.ResourceAccess]@{
            Id = "50483e42-d915-4231-9639-7fdb7fd190e5";
            Type = "Role"},
        [Microsoft.Open.AzureAD.Model.ResourceAccess]@{
            Id = "37730810-e9ba-4e46-b07e-8ca78d182097";
            Type = "Role"},
        [Microsoft.Open.AzureAD.Model.ResourceAccess]@{
            Id = "4ad84827-5578-4e18-ad7a-86530b12f884";
            Type = "Scope"},
        [Microsoft.Open.AzureAD.Model.ResourceAccess]@{
            Id = "e0a7cdbb-08b0-4697-8264-0069786e9674";
            Type = "Scope"},
        [Microsoft.Open.AzureAD.Model.ResourceAccess]@{
            Id = "7427e0e9-2fba-42fe-b0c0-848c9e6a8182";
            Type = "Scope"},
        [Microsoft.Open.AzureAD.Model.ResourceAccess]@{
            Id = "572fea84-0151-49b2-9301-11cb16974376";
            Type = "Scope"},
        [Microsoft.Open.AzureAD.Model.ResourceAccess]@{
            Id = "e4c9e354-4dc5-45b8-9e7c-e1393b0b1a20";
            Type = "Scope"},
        [Microsoft.Open.AzureAD.Model.ResourceAccess]@{
            Id = "f1493658-876a-4c87-8fa7-edb559b3476a";
            Type = "Scope"},
        [Microsoft.Open.AzureAD.Model.ResourceAccess]@{
            Id = "4edf5f54-4666-44af-9de9-0144fb4b6e8c";
            Type = "Scope"},
        [Microsoft.Open.AzureAD.Model.ResourceAccess]@{
            Id = "314874da-47d6-4978-88dc-cf0d37f0bb82";
            Type = "Scope"},
        [Microsoft.Open.AzureAD.Model.ResourceAccess]@{
            Id = "02e97553-ed7b-43d0-ab3c-f8bace0d040c";
            Type = "Scope"},
        [Microsoft.Open.AzureAD.Model.ResourceAccess]@{
            Id = "89fe6a52-be36-487e-b7d8-d061c450a026";
            Type = "Scope"},
        [Microsoft.Open.AzureAD.Model.ResourceAccess]@{
            Id = "37f7f235-527c-4136-accd-4a02d197296e";
            Type = "Scope"},
        [Microsoft.Open.AzureAD.Model.ResourceAccess]@{
            Id = "14dad69e-099b-42c9-810b-d002981feec1";
            Type = "Scope"},
        [Microsoft.Open.AzureAD.Model.ResourceAccess]@{
            Id = "b7887744-6746-4312-813d-72daeaee7e2d";
            Type = "Scope"},
        [Microsoft.Open.AzureAD.Model.ResourceAccess]@{
            Id = "951183d1-1a61-466f-a6d1-1fde911bfd95";
            Type = "Scope"}
}

$partnerCenterAppAccess = [Microsoft.Open.AzureAD.Model.RequiredResourceAccess]@{
    ResourceAppId = "fa3d9a0c-3fb0-42cc-9193-47c7ecd2edbd";
    ResourceAccess =
        [Microsoft.Open.AzureAD.Model.ResourceAccess]@{
            Id = "1cebfa2a-fb4d-419e-b5f9-839b4383e05a";
            Type = "Scope"}
}

$SessionInfo = Get-AzureADCurrentSessionInfo

Write-Host -ForegroundColor Green "Creating the Azure AD application and related resources..."

$app = New-AzureADApplication -AvailableToOtherTenants $true -DisplayName $DisplayName -IdentifierUris "https://$($SessionInfo.TenantDomain)/$((New-Guid).ToString())" -RequiredResourceAccess $adAppAccess, $graphAppAccess, $partnerCenterAppAccess -ReplyUrls @("urn:ietf:wg:oauth:2.0:oob","https://localhost","http://localhost","http://localhost:8400")
$password = New-AzureADApplicationPasswordCredential -ObjectId $app.ObjectId
$spn = New-AzureADServicePrincipal -AppId $app.AppId -DisplayName $DisplayName


    $adminAgentsGroup = Get-AzureADGroup -Filter "DisplayName eq 'AdminAgents'"
    Add-AzureADGroupMember -ObjectId $adminAgentsGroup.ObjectId -RefObjectId $spn.ObjectId

write-host "Installing PartnerCenter Module." -ForegroundColor Green
install-module PartnerCenter -Force
write-host "Sleeping for 30 seconds to allow app creation on O365" -foregroundcolor green
start-sleep 30
write-host "Please approve General consent form." -ForegroundColor Green
$PasswordToSecureString = $password.value | ConvertTo-SecureString -asPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($($app.AppId),$PasswordToSecureString)
$token = New-PartnerAccessToken -ApplicationId "$($app.AppId)" -Scopes 'https://api.partnercenter.microsoft.com/user_impersonation' -ServicePrincipal -Credential $credential -Tenant $($spn.AppOwnerTenantID) -UseAuthorizationCode
write-host "Please approve Exchange consent form." -ForegroundColor Green
$Exchangetoken = New-PartnerAccessToken -ApplicationId 'a0c73c16-a7e3-4564-9a95-2bdf47383716' -Scopes 'https://outlook.office365.com/.default' -Tenant $($spn.AppOwnerTenantID) -UseDeviceAuthentication
write-host "Please approve Azure consent form." -ForegroundColor Green
$Azuretoken = New-PartnerAccessToken -ApplicationId "$($app.AppId)" -Scopes 'https://management.azure.com/user_impersonation' -ServicePrincipal -Credential $credential -Tenant $($spn.AppOwnerTenantID) -UseAuthorizationCode
write-host "Last initation required: Please browse to https://login.microsoftonline.com/$($spn.AppOwnerTenantID)/adminConsent?client_id=$($app.AppId)"
write-host "Press any key after auth. An error report about incorrect URIs is expected!"
[void][System.Console]::ReadKey($true)
Write-Host "######### Secrets #########"
Write-Host "`$ApplicationId         = '$($app.AppId)'"
Write-Host "`$ApplicationSecret     = '$($password.Value)'"
Write-Host "`$TenantID              = '$($spn.AppOwnerTenantID)'"
write-host "`$RefreshToken          = '$($token.refreshtoken)'" -ForegroundColor Blue
write-host "`$ExchangeRefreshToken = '$($ExchangeToken.Refreshtoken)'" -ForegroundColor Green
write-host "`$AzureRefreshToken =   '$($Azuretoken.Refreshtoken)'" -ForegroundColor Magenta
Write-Host "######### Secrets #########"
Write-Host "    SAVE THESE IN A SECURE LOCATION     " 