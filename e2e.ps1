Param (
    [Parameter(Mandatory = $true)]
    [string] $NewTenantName,

    [Parameter(ValueFromPipelineByPropertyName)]
    [string] $OrganizationName,
    [string] $AppName = "test-auto-app",
    [string] $AppReplyUrl = "http://localhost:3000",
    [string] $FlowName = "susiv2",

    [Parameter(ParameterSetName = 'UiCustomization')]
    [string] $ResourceGroupName,
    [Parameter(ParameterSetName = 'UiCustomization')]
    [string] $UiStoreName = $NewTenantName,
    [Parameter(ParameterSetName = 'UiCustomization')]
    [string] $UiStoreContainerName = "b2cui",
    [Parameter(ParameterSetName = 'UiCustomization')]
    [string] $SubscriptionId,
    [Parameter(ParameterSetName = 'UiCustomization')]
    [string] $SubscriptionTenantId,
    [Parameter(ParameterSetName = 'UiCustomization')]
    [string] $LocationOverride = "eastus",
    [switch] $UiCustomization = $FALSE
)

function Add-Tenant {
    param (
        [string]$orgName,
        [string]$tenantName,
        [string]$country = "US",
        $token
    )

    if ($orgName -eq "") {
        $orgName = $tenantName
    }

    $payload = "{companyName: `"$orgName`", countryCode: `"$country`", initialDomainPrefix: `"$tenantName`"}";
    return Invoke-AuthenticatedPost -endpoint "https://main.iam.ad.ext.azure.com/api/Directories/B2C" -payload $payload -token $token
}

function Add-ApplicationRegistration {
    param (
        [string]$appName,
        [string]$tenantName,
        [string]$appReplyUrl,
        $token
    )

    $payload = Get-Content .\api-templates\app-registration.json -Raw
    $payload = $payload.Replace("`$appName", $appName).Replace("`$appReplyUrl", $appReplyUrl);

    return Invoke-AuthenticatedPost -endpoint "https://main.b2cadmin.ext.azure.com/api/ApplicationV2/PostNewApplication?tenantId=$tenantName" -payload $payload -token $token
}

function Add-StandardSusiUserFlow {
    param (
        [string]$tenantName,
        [string]$flowName,
        [string]$flowType = "B2CSignUpOrSignInWithPassword_V2",
        [switch]$uiCustomization,
        [string]$customUiPageRootUrl,
        [string]$rootCustomizationPath = ".\ui",
        $token
    )

    $content = [System.String]::Empty;

    if ($uiCustomization) {
        $contentTemplate = Get-Content .\api-templates\contentDefinitions.json -Raw
        $contentData = Find-MatchingUiFiles -rootPath $rootCustomizationPath -tenantName $tenantName -customUiPageRootUrl $customUiPageRootUrl
        $content = $contentTemplate.Replace("`$contentDefinitions", $contentData);
    }

    $payload = Get-Content .\api-templates\flow.json -Raw
    $payload = $payload.Replace("`$flowName", $flowName).Replace("`$flowType", $flowType).Replace("`$contentDefinitions", $content);
    return Invoke-AuthenticatedPost -endpoint "https://main.b2cadmin.ext.azure.com/api/adminuserjourneys?tenantId=$tenantName.onmicrosoft.com" -payload $payload -token $token
}

function Find-MatchingUiFiles {
    param(
        [string] $rootPath,
        [string] $tenantName,
        [string] $customUiPageRootUrl
    )
   
    $pages = [System.Collections.Generic.Dictionary[string, string]]::new()
    $pages.Add("phonefactor.html", "api.phonefactor");
    $pages.Add("resetpassword.html", "api.localaccountpasswordreset");
    $pages.Add("selfAsserted.html", "api.selfasserted.blockminor");
    $pages.Add("unified.html", "api.signinandsignupwithpassword");
    $pages.Add("updateprofile.html", "api.selfasserted.profileupdate");
    $customizations = [System.Collections.Generic.List[string]]::new();

    foreach ($page in $pages.GetEnumerator()) {
        $p = Get-ChildItem -Path $rootPath -Recurse -Filter $page.Key
        if ($NULL -eq $p) { continue };
        $definition = Add-UiCustomizations -contentApiDefinition $page.Value -tenantName $tenantName -displayName $page.Value -originalPageUri $page.Key.Replace(".html", ".cshtml") -customUiContentUrl ($customUiPageRootUrl + $p.Name)
        $customizations.Add($definition)
    }
    return [System.String]::Join(',', $customizations);
}

function Add-UiCustomizations {
    param (
        [string]$contentApiDefinition,
        [string]$tenantName,
        [string]$displayName,
        [string]$originalPageUri,
        [string]$customUiContentUrl
    )

    $payload = Get-Content .\api-templates\contentDefinition.json -Raw
    $payload = $payload.Replace("`$contentApiDefinition", $contentApiDefinition).Replace("`$tenantName", $tenantName).Replace("`$DisplayName", $displayName).Replace("`$originalPageUri", $originalPageUri).Replace("`$customUiContentUrl", $customUiContentUrl);
    return $payload;
} 

function Add-AzureBlobStorageAccount {
    param(
        [string] $rgName,
        [string] $storageName,
        [string] $tenantUrl,
        [string] $subId,
        [string] $subTenantId
    )
    
    if ($subTenantId -eq "") {
        Select-AzSubscription -Subscription $subId
    }
    else {
        Select-AzSubscription -Subscription $subId -Tenant $subTenantId
    }

    $rg = Get-AzResourceGroup -Name $rgName -ErrorAction SilentlyContinue -ErrorVariable rgNotExists
    if ($rgNotExists) {
        $rg = New-AzResourceGroup -Name $rgName -Location $LocationOverride
    }

    $location = $rg.Location

    $storage = Get-AzStorageAccount -ResourceGroupName $rgName -Name $storageName -ErrorAction SilentlyContinue

    if ($NULL -eq $storage) {
        $storage = New-AzStorageAccount -ResourceGroupName $rgName -Name $storageName -SkuName Standard_LRS -Location $location -Kind StorageV2
    }

    $CorsRules = (@{AllowedOrigins = @("https://$tenantUrl"); AllowedHeaders = @("*"); ExposedHeaders = @("*"); MaxAgeInSeconds = 200; AllowedMethods = @("GET", "PUT", "OPTIONS") })
    Set-AzStorageCORSRule -ServiceType Blob -CorsRules $CorsRules -Context $storage.Context
    return $storage;

}

function Add-UiStoreContainer {
    param(
        [string]$containerName,
        $ctx
    )

    $container = Get-AzStorageContainer -Name $containerName -Context $ctx -ErrorAction SilentlyContinue

    if ($NULL -eq $container) {
        $container = New-AzStorageContainer -Name $containerName -Context $ctx -Permission blob
    }
    return $container;
}

function Add-UiFilesToContainer {
    param(
        [string]$localRootPath,
        [string]$containerName,
        $ctx
    )
    Get-ChildItem -Path $localRootPath -file -Recurse | Set-AzStorageBlobContent -Container $containerName -Context $ctx -Force
}

function Add-AzureResourceLinkToB2C {
    # todo: this
}

function Invoke-AuthenticatedPost {
    param (
        [string]$endpoint,
        [string]$payload,
        $token
    )
    $headers = @{"Authorization" = "Bearer $($token.AccessToken)"
        'X-Requested-With'       = 'XMLHttpRequest'
        'x-ms-client-request-id' = [guid]::NewGuid()
        'x-ms-correlation-id'    = [guid]::NewGuid()
        'Content-Type'           = "application/json"
    }

    Write-Debug "Sending payload to $endpoint"
    Write-Debug "payload $payload"
    #Write-Host token $token.AccessToken 

    return Invoke-RestMethod $endpoint -Headers $headers -Method POST -Body $payload
}

function Write-Details {
    param (
        [string]$newTenantId,
        [string]$appId,
        [string]$flowId,
        [string]$replyUrl
    )
    Write-Host Your new tenant and app are created!
    Write-Host Tenant: -NoNewline
    Write-Host -ForegroundColor Green $newTenantId
    Write-Host App ID: -NoNewline
    Write-Host -ForegroundColor Green $appId
    Write-Host Susi flow: -NoNewline
    Write-Host -ForegroundColor Green $flowId
    Write-Host Dev reply url: -NoNewline
    Write-Host -ForegroundColor Green $replyUrl
    # todo: make sure this works on pscore
    $encodedUrl = [System.Web.HttpUtility]::UrlEncode($replyUrl)
    Write-Host -NoNewline Signin URL: "https://" 
    Write-Host -NoNewLine -ForegroundColor Green $NewTenantName
    Write-Host -NoNewLine ".b2clogin.com/" 
    Write-Host -NoNewline -ForegroundColor Green $newTenantId
    Write-Host -NoNewline "/oauth2/v2.0/authorize?p="
    Write-Host -NoNewline -ForegroundColor Green $addFlowResponse.id
    Write-Host -NoNewline "&client_id="
    Write-Host -NoNewline -ForegroundColor Green $appId
    Write-Host -NoNewLine "&nonce=defaultNonce&redirect_uri="
    Write-Host -NoNewLine -ForegroundColor Green $encodedUrl
    Write-Host "&scope=openid&response_type=id_token&prompt=login"
}

function Get-Token {
    param(
        [string]$resource,
        [string]$tenant,
        [bool]$retry
    )
    $context = Get-AzContext
    if ($tenant -eq "") {
        $tenant = $context.Tenant.Id
    }

    try {
        $token = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate(
            $context.Account, $context.Environment, $tenant, $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, $resource)
        return $token;
    }
    catch {
        Write-Host $_.Exception.Message
        Write-Host Please login to your Azure Account:
        Connect-AzAccount
        if ($retry -eq $FALSE) {
            Get-Token -resource $resource -tenant $tenant -retry $true
        }
    }
}

# authenticates as ibiza :/
$token = Get-Token -resource "74658136-14ec-4630-ad9b-26e160ff0fc6" -ErrorAction Stop
if ($NULL -eq $token.AccessToken -or $token.AccessToken -eq "") {
    Write-Host "Token not available, try logging in with Connect-AzAccount"
    return;
}

Write-Host "Creating tenant $NewTenantName.onmicrosoft.com...this may take a while...zzz..."
$newTenantId = Add-Tenant -orgName $OrganizationName -tenantName $NewTenantName -token $token
# re-authenticate in the b2c tenant
$b2cToken = Get-Token -resource "https://management.core.windows.net/" -tenant $newTenantId
$addAppResponse = Add-ApplicationRegistration -appName $AppName -appReplyUrl $AppReplyUrl -tenantName $newTenantId -token $b2cToken

# todo: add discovery of more pages, versions, etc for ui customization
$customUiPageRootUrl = "https://$UiStoreName.blob.core.windows.net/$UiStoreContainerName/"

if ($PSCmdlet.ParameterSetName -eq "UiCustomization" -or $UiCustomization) {
    # todo: link tenant to subscription - requires azure sub & resource group 
    $uiStore = Add-AzureBlobStorageAccount -rgName $ResourceGroupName -storageName $UiStoreName -tenantUrl "$NewTenantName.b2clogin.com" -subId $SubscriptionId -subTenantId $SubscriptionTenantId
    $container = Add-UiStoreContainer -containerName $UiStoreContainerName -ctx $uiStore.Context
    Add-UiFilesToContainer -localRootPath $(Resolve-Path -Path ui) -containerName $container.Name -ctx $uiStore.Context
    $addFlowResponse = Add-StandardSusiUserFlow -tenantId $newTenantId -token $b2cToken -flowName $FlowName -customUiPageRootUrl $customUiPageRootUrl -tenantName $NewTenantName -uiCustomization
}
else {
    $addFlowResponse = Add-StandardSusiUserFlow -tenantId $newTenantId -token $b2cToken -flowName $FlowName -tenantName $NewTenantName
}

Write-Details -newTenantId $newTenantId -appId $addAppResponse.applicationId -flowId $addFlowResponse.id -replyUrl $AppReplyUrl