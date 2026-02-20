param(
    [Parameter(Mandatory = $true)]
    [string]$FunctionAppName,

    [Parameter(Mandatory = $true)]
    [string]$ResourceGroup,

    [string]$ProjectPath = "$HOME/SamlCertRotation/src/SamlCertRotation"
)

$ErrorActionPreference = 'Stop'

Set-Location $ProjectPath

dotnet publish -c Release
func azure functionapp publish $FunctionAppName --dotnet-isolated --force

az functionapp sync-functions --resource-group $ResourceGroup --name $FunctionAppName | Out-Null
az functionapp restart --resource-group $ResourceGroup --name $FunctionAppName | Out-Null
Start-Sleep -Seconds 20

$functionNames = az functionapp function list --resource-group $ResourceGroup --name $FunctionAppName --query "[].name" -o tsv
if ([string]::IsNullOrWhiteSpace($functionNames)) {
    throw "No functions were indexed after publish. Deployment is unhealthy."
}

$functionHost = az functionapp show --resource-group $ResourceGroup --name $FunctionAppName --query defaultHostName -o tsv

$statusCode = $null
try {
    Invoke-WebRequest "https://$functionHost/api/dashboard/stats" -UseBasicParsing | Out-Null
    $statusCode = 200
}
catch {
    $statusCode = $_.Exception.Response.StatusCode.value__
}

Write-Host "Function app deployment completed."
Write-Host "Indexed functions:" 
$functionNames
Write-Host "Route health status code: $statusCode"
if ($statusCode -eq 404) {
    throw "Route health check returned 404 after deployment."
}
